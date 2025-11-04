#!/usr/bin/env python3
"""
SQLite Database Search Tool

This script recursively searches through a directory for SQLite database files
(regardless of file extension) and searches for one or more strings case-insensitively.
Alternatively, it can scan specific SQLite files from a list file (e.g., discovered.txt).

Usage:
    python sqlite_search.py <target_directory> <comma_separated_search_strings> [--folders|--list]
    
Options:
    --folders, -f: Comma-separated folders to target (e.g., Microsoft,Mozilla,Google)
    --list, -l: Path to file containing SQLite file paths to scan (one per line, e.g., discovered.txt)
    --workers, -w: Number of concurrent workers (default: 4)
    --verbose, -v: Enable verbose logging
    --no-clear, --append: Do not clear discovered.txt at start, append to existing file instead

Example:
    python sqlite_search.py "C:\\Investigation\\a.smith\\AppData" "zaffrevelox"
    python sqlite_search.py "C:\\Investigation\\a.smith\\AppData" "zaffrevelox,password,email"
    python sqlite_search.py "C:\\Investigation\\a.smith\\AppData" "zaffrevelox" --folders Microsoft,Mozilla,Google
    python sqlite_search.py "C:\\Investigation\\a.smith\\AppData" "zaffrevelox" --list discovered.txt
    python sqlite_search.py "C:\\Investigation\\a.smith\\AppData" "zaffrevelox" --no-clear
    python3 sqlite_search.py "/mnt/c/Investigation/a.smith/AppData" "zaffrevelox,13221442.hta,pfusioncaptcha.com,news.axonbyte.org,captcha_privacy.epub,cmd.exe /c for /r" --folders Microsoft,Mozilla,Google
"""

import os
import sys
import sqlite3
import argparse
from pathlib import Path
from typing import List, Tuple, Optional
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('sqlite_search.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class SQLiteSearcher:
    """A class to search for strings in SQLite databases."""
    
    def __init__(self, target_directory: str, search_strings: List[str], target_folders: List[str] = None, max_workers: int = 4, clear_discovered: bool = True):
        self.target_directory = Path(target_directory)
        self.search_strings = [s.lower() for s in search_strings]  # Store as lowercase for case-insensitive search
        self.target_folders = target_folders or []  # List of specific folders to search in
        self.found_matches = []
        self.processed_files = 0
        self.sqlite_files_found = 0
        self.discovered_files = set()  # Set of discovered SQLite file paths (for fast lookup)
        self.total_matches = 0  # Cumulative total matches
        self.discovered_file_path = Path('discovered.txt')  # Path to save discovered files
        self.max_workers = max_workers  # Number of concurrent workers
        self.lock = threading.Lock()  # Lock for thread-safe operations
        self.clear_discovered = clear_discovered  # Whether to clear discovered.txt at start
    
    def load_existing_discovered_files(self) -> None:
        """
        Load existing file paths from discovered.txt to avoid duplicates when appending.
        """
        if not self.discovered_file_path.exists():
            return
        
        try:
            with open(self.discovered_file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    file_path = line.strip()
                    if file_path:
                        self.discovered_files.add(file_path)
            logger.debug(f"Loaded {len(self.discovered_files)} existing entries from discovered.txt")
        except Exception as e:
            logger.warning(f"Could not load existing discovered.txt: {e}")
        
    def is_sqlite_file(self, file_path: Path) -> bool:
        """
        Check if a file is a valid SQLite database by attempting to open it.
        
        Args:
            file_path: Path to the file to check
            
        Returns:
            bool: True if the file is a valid SQLite database, False otherwise
        """
        try:
            # Check file size (SQLite files should be at least 96 bytes for header)
            file_size = file_path.stat().st_size
            if file_size < 96:
                return False
                
            # Try to open as SQLite database
            # Use URI format with read-only mode to avoid issues with locked files
            db_path = str(file_path)
            try:
                with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
                    # Try to execute a simple query to verify it's a valid SQLite DB
                    cursor = conn.cursor()
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' LIMIT 1")
                    cursor.fetchone()
                    return True
            except sqlite3.OperationalError:
                # If URI format fails, try regular connection
                with sqlite3.connect(db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' LIMIT 1")
                    cursor.fetchone()
                    return True
                
        except (sqlite3.DatabaseError, sqlite3.Error) as e:
            logger.debug(f"File is not a valid SQLite database {file_path}: {e}")
            return False
        except (OSError, IOError, PermissionError) as e:
            logger.debug(f"Cannot access file {file_path}: {e}")
            return False
        except Exception as e:
            logger.debug(f"Unexpected error checking {file_path}: {e}")
            return False
    
    def search_in_database(self, db_path: Path) -> List[Tuple[str, str, str, str]]:
        """
        Search for the target strings in all tables and columns of a SQLite database.
        
        Args:
            db_path: Path to the SQLite database
            
        Returns:
            List of tuples containing (table_name, column_name, row_data, matched_string) where matches were found
        """
        matches = []
        
        try:
            with sqlite3.connect(str(db_path)) as conn:
                cursor = conn.cursor()
                
                # Get all tables in the database
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = cursor.fetchall()
                
                for (table_name,) in tables:
                    try:
                        # Get column information for the table
                        cursor.execute(f"PRAGMA table_info({table_name})")
                        columns_info = cursor.fetchall()
                        
                        if not columns_info:
                            continue
                            
                        # Get all data from the table
                        cursor.execute(f"SELECT * FROM {table_name}")
                        rows = cursor.fetchall()
                        
                        # Search through each row and column
                        for row_idx, row in enumerate(rows):
                            for col_idx, cell_value in enumerate(row):
                                if cell_value is not None:
                                    # Convert to string and search case-insensitively
                                    cell_str = str(cell_value)
                                    cell_lower = cell_str.lower()
                                    
                                    # Check against all search strings
                                    for search_string in self.search_strings:
                                        if search_string in cell_lower:
                                            column_name = columns_info[col_idx][1] if col_idx < len(columns_info) else f"column_{col_idx}"
                                            matches.append((table_name, column_name, cell_str, search_string))
                                            break  # Only add one match per cell, even if multiple strings match
                                        
                    except sqlite3.Error as e:
                        logger.warning(f"Error processing table {table_name} in {db_path}: {e}")
                        continue
                        
        except sqlite3.Error as e:
            logger.error(f"Error accessing database {db_path}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error processing {db_path}: {e}")
            
        return matches
    
    def should_scan_directory(self, dir_path: Path) -> bool:
        """
        Check if a directory should be scanned based on target folder filters.
        
        Args:
            dir_path: Path to the directory to check
            
        Returns:
            bool: True if the directory should be scanned, False otherwise
        """
        if not self.target_folders:
            return True  # No filters, scan everything
            
        # Check if any part of the path contains our target folders
        path_parts = [part.lower() for part in dir_path.parts]
        for target_folder in self.target_folders:
            if target_folder.lower() in path_parts:
                return True
        return False
    
    def save_discovered_file(self, file_path: Path) -> None:
        """
        Save discovered SQLite file path to discovered.txt in real-time (thread-safe).
        
        Args:
            file_path: Path to the discovered SQLite file
        """
        with self.lock:
            # Use absolute path for consistency
            try:
                file_str = str(file_path.resolve())
            except Exception:
                file_str = str(file_path)
            
            if file_str not in self.discovered_files:
                self.discovered_files.add(file_str)
                try:
                    # Open in append mode and flush immediately to ensure real-time updates
                    with open(self.discovered_file_path, 'a', encoding='utf-8') as f:
                        f.write(f"{file_str}\n")
                        f.flush()  # Force immediate write to disk buffer
                        try:
                            os.fsync(f.fileno())  # Ensure data is written to disk (may fail on some systems)
                        except (OSError, AttributeError):
                            # Some systems or file handles don't support fsync, that's okay
                            pass
                    logger.debug(f"Saved to discovered.txt: {file_str}")
                except Exception as e:
                    logger.warning(f"Failed to write to discovered.txt: {e}")
    
    def process_sqlite_file(self, file_path: Path) -> None:
        """
        Process a single SQLite file: check if valid, search for matches, and save to discovered.txt.
        
        Args:
            file_path: Path to the SQLite file to process
        """
        try:
            # Check if file is a SQLite database
            if self.is_sqlite_file(file_path):
                with self.lock:
                    self.sqlite_files_found += 1
                
                # Get file information for logging
                try:
                    file_size = file_path.stat().st_size
                    file_size_mb = file_size / (1024 * 1024)
                    absolute_path = file_path.resolve()
                    logger.info(f"Found SQLite database [{self.sqlite_files_found}] - Location: {absolute_path} (Size: {file_size_mb:.2f} MB)")
                except Exception as e:
                    logger.info(f"Found SQLite database [{self.sqlite_files_found}] - Location: {file_path}")
                
                # Save discovered file
                self.save_discovered_file(file_path)
                
                # Search for matches in this database
                matches = self.search_in_database(file_path)
                
                if matches:
                    with self.lock:
                        self.total_matches += len(matches)
                        total = self.total_matches
                        logger.info(f"Found {len(matches)} matches in {file_path} (Total matches so far: {total})")
                        
                        for table_name, column_name, content, matched_string in matches:
                            self.found_matches.append({
                                'file_path': str(file_path),
                                'table_name': table_name,
                                'column_name': column_name,
                                'content': content,
                                'matched_string': matched_string
                            })
                            logger.info(f"  Table: {table_name}, Column: {column_name}, Matched: '{matched_string}'")
                            logger.info(f"  Content: {content[:200]}{'...' if len(content) > 200 else ''}")
                else:
                    logger.debug(f"No matches found in {file_path}")
            else:
                # File exists and meets size requirement but is not a valid SQLite database
                logger.debug(f"File is not a valid SQLite database: {file_path}")
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")
    
    def scan_directory(self) -> None:
        """
        Recursively scan the target directory for SQLite files and search for the target string.
        Uses concurrent processing to search multiple databases in parallel.
        """
        logger.info(f"Starting scan of directory: {self.target_directory}")
        search_strings_quoted = ', '.join([f"'{s}'" for s in self.search_strings])
        logger.info(f"Searching for strings: {search_strings_quoted} (case-insensitive)")
        logger.info(f"Using {self.max_workers} concurrent workers for database processing")
        
        if self.target_folders:
            logger.info(f"Targeting specific folders: {', '.join(self.target_folders)}")
        
        if not self.target_directory.exists():
            logger.error(f"Target directory does not exist: {self.target_directory}")
            return
        
        if not self.target_directory.is_dir():
            logger.error(f"Target path is not a directory: {self.target_directory}")
            return
        
        # Check if directory is readable
        try:
            if not os.access(self.target_directory, os.R_OK):
                logger.error(f"Target directory is not readable: {self.target_directory}")
                return
        except Exception as e:
            logger.error(f"Cannot access target directory {self.target_directory}: {e}")
            return
        
        # Initialize discovered.txt file (clear it or load existing entries)
        if self.clear_discovered:
            try:
                with open(self.discovered_file_path, 'w', encoding='utf-8') as f:
                    f.write("")  # Clear existing file
                logger.info("Cleared discovered.txt for new scan")
            except Exception as e:
                logger.warning(f"Could not initialize discovered.txt: {e}")
        else:
            # Load existing entries to avoid duplicates
            self.load_existing_discovered_files()
            if self.discovered_files:
                logger.info(f"Appending to discovered.txt (loaded {len(self.discovered_files)} existing entries)")
            else:
                logger.info("Appending to discovered.txt (file is empty or doesn't exist)")
        
        # Collect all candidate files first
        candidate_files = []
        large_files_skipped = 0
        small_files_skipped = 0
        errors_encountered = 0
        
        logger.info(f"Collecting candidate files from {self.target_directory}...")
        try:
            walk_iterator = os.walk(self.target_directory)
        except Exception as e:
            logger.error(f"Cannot walk directory {self.target_directory}: {e}")
            return
        
        for root, dirs, files in walk_iterator:
            root_path = Path(root)
            
            # Check if we should scan this directory
            if not self.should_scan_directory(root_path):
                logger.debug(f"Skipping directory (not in target folders): {root_path}")
                continue
                
            for file in files:
                file_path = Path(root) / file
                self.processed_files += 1
                
                # Skip very large files (> 100MB) to avoid memory issues
                try:
                    file_size = file_path.stat().st_size
                    if file_size > 100 * 1024 * 1024:  # 100MB
                        large_files_skipped += 1
                        logger.debug(f"Skipping large file: {file_path} ({file_size / (1024*1024):.1f} MB)")
                        continue
                    # Only add files that might be SQLite (check size threshold)
                    if file_size >= 96:  # Minimum SQLite file size
                        candidate_files.append(file_path)
                    else:
                        small_files_skipped += 1
                except OSError as e:
                    errors_encountered += 1
                    logger.debug(f"Cannot access file {file_path}: {e}")
                    continue
                
                # Progress indicator
                if self.processed_files % 1000 == 0:
                    with self.lock:
                        logger.info(f"Collected {len(candidate_files)} candidate files from {self.processed_files} files processed, found {self.sqlite_files_found} SQLite databases, total matches: {self.total_matches}")
        
        with self.lock:
            logger.info(f"File collection complete: {self.processed_files} total files examined, {len(candidate_files)} candidate files, {self.sqlite_files_found} SQLite databases found, {large_files_skipped} large files skipped, {small_files_skipped} small files skipped, {errors_encountered} errors, total matches: {self.total_matches}")
        
        if self.processed_files == 0:
            logger.warning(f"No files found in directory {self.target_directory}. Check if the directory is empty or inaccessible.")
            return
        
        # Process candidate files concurrently
        if len(candidate_files) == 0:
            logger.warning(f"No candidate files found to process. Check if the directory contains files >= 96 bytes.")
            return
        
        logger.info(f"Processing {len(candidate_files)} candidate files with {self.max_workers} workers...")
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all file processing tasks
            future_to_file = {executor.submit(self.process_sqlite_file, file_path): file_path 
                            for file_path in candidate_files}
            
            # Process completed tasks
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    future.result()  # This will raise any exceptions that occurred
                except Exception as e:
                    logger.error(f"Error processing {file_path}: {e}")
        
        logger.info(f"Scan completed. Processed {self.processed_files} files, found {self.sqlite_files_found} SQLite databases, total matches: {self.total_matches}")
    
    def scan_from_list(self, list_file_path: Path) -> None:
        """
        Scan specific SQLite files from a list file (e.g., discovered.txt).
        Uses concurrent processing to search multiple databases in parallel.
        
        Args:
            list_file_path: Path to the file containing SQLite file paths (one per line)
        """
        logger.info(f"Starting scan from list file: {list_file_path}")
        search_strings_quoted = ', '.join([f"'{s}'" for s in self.search_strings])
        logger.info(f"Searching for strings: {search_strings_quoted} (case-insensitive)")
        logger.info(f"Using {self.max_workers} concurrent workers for database processing")
        
        # Load existing entries from discovered.txt if not clearing
        if not self.clear_discovered:
            self.load_existing_discovered_files()
            if self.discovered_files:
                logger.info(f"Appending to discovered.txt (loaded {len(self.discovered_files)} existing entries)")
            else:
                logger.info("Appending to discovered.txt (file is empty or doesn't exist)")
        
        if not list_file_path.exists():
            logger.error(f"List file does not exist: {list_file_path}")
            return
        
        # Read file paths from the list file
        candidate_files = []
        try:
            with open(list_file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    file_path_str = line.strip()
                    if not file_path_str or file_path_str.startswith('#'):  # Skip empty lines and comments
                        continue
                    
                    file_path = Path(file_path_str)
                    if not file_path.exists():
                        logger.warning(f"File from list does not exist (line {line_num}): {file_path}")
                        continue
                    
                    # Skip very large files (> 100MB) to avoid memory issues
                    try:
                        if file_path.stat().st_size > 100 * 1024 * 1024:  # 100MB
                            logger.debug(f"Skipping large file: {file_path}")
                            continue
                        # Only add files that might be SQLite (check size threshold)
                        if file_path.stat().st_size >= 96:  # Minimum SQLite file size
                            candidate_files.append(file_path)
                    except OSError as e:
                        logger.warning(f"Cannot access file from list (line {line_num}): {file_path} - {e}")
                        continue
        
        except Exception as e:
            logger.error(f"Error reading list file {list_file_path}: {e}")
            return
        
        if not candidate_files:
            logger.warning("No valid files found in the list file")
            return
        
        logger.info(f"Found {len(candidate_files)} files to process from list")
        
        # Process candidate files concurrently
        logger.info(f"Processing {len(candidate_files)} files with {self.max_workers} workers...")
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all file processing tasks
            future_to_file = {executor.submit(self.process_sqlite_file, file_path): file_path 
                            for file_path in candidate_files}
            
            # Process completed tasks
            completed_count = 0
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    future.result()  # This will raise any exceptions that occurred
                except Exception as e:
                    logger.error(f"Error processing {file_path}: {e}")
                
                # Progress indicator
                completed_count += 1
                with self.lock:
                    if len(candidate_files) > 10 and completed_count % max(1, len(candidate_files) // 10) == 0:
                        logger.info(f"Progress: {completed_count}/{len(candidate_files)} files processed, found {self.sqlite_files_found} SQLite databases, total matches: {self.total_matches}")
        
        logger.info(f"Scan completed. Processed {len(candidate_files)} files from list, found {self.sqlite_files_found} SQLite databases, total matches: {self.total_matches}")
    
    def generate_report(self) -> None:
        """
        Generate a summary report of the search results.
        """
        print("\n" + "="*80)
        print("SQLITE SEARCH REPORT")
        print("="*80)
        print(f"Target Directory: {self.target_directory}")
        search_strings_quoted = ', '.join([f"'{s}'" for s in self.search_strings])
        print(f"Search Strings: {search_strings_quoted} (case-insensitive)")
        print(f"Total Files Processed: {self.processed_files}")
        print(f"SQLite Databases Found: {self.sqlite_files_found}")
        print(f"Total Matches Found: {self.total_matches}")
        print(f"Discovered SQLite files saved to: {self.discovered_file_path}")
        print("="*80)
        
        if self.found_matches:
            print("\nMATCHES FOUND:")
            print("-" * 40)
            for i, match in enumerate(self.found_matches, 1):
                print(f"\nMatch #{i}:")
                print(f"  File: {match['file_path']}")
                print(f"  Table: {match['table_name']}")
                print(f"  Column: {match['column_name']}")
                print(f"  Matched String: '{match['matched_string']}'")
                print(f"  Content: {match['content']}")
        else:
            print("\nNo matches found.")
        
        print("\n" + "="*80)


def main():
    """Main function to run the SQLite search tool."""
    parser = argparse.ArgumentParser(
        description="Search for strings in SQLite databases",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sqlite_search.py "C:\\Investigation\\a.smith\\AppData" "zaffrevelox"
  python sqlite_search.py "C:\\Investigation\\a.smith\\AppData" "zaffrevelox,password,email"
  python sqlite_search.py "C:\\Users\\User\\AppData" "password" --verbose
  python sqlite_search.py "C:\\Investigation\\a.smith\\AppData" "zaffrevelox" --folders Microsoft,Mozilla,Google
  python sqlite_search.py "C:\\Investigation\\a.smith\\AppData" "zaffrevelox" --list discovered.txt
  python sqlite_search.py "C:\\Investigation\\a.smith\\AppData" "zaffrevelox" --no-clear
        """
    )
    
    parser.add_argument(
        'directory',
        nargs='?',
        help='Target directory to search in (required when using --folders, optional when using --list)'
    )
    
    parser.add_argument(
        'search_strings',
        help='Comma-separated strings to search for (case-insensitive)'
    )
    
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        '--folders', '-f',
        help='Comma-separated folders to target (e.g., Microsoft,Mozilla,Google). Mutually exclusive with --list.'
    )
    group.add_argument(
        '--list', '-l',
        help='Path to file containing SQLite file paths to scan (one per line, e.g., discovered.txt). Mutually exclusive with --folders.'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--workers', '-w',
        type=int,
        default=4,
        help='Number of concurrent workers for database processing (default: 4)'
    )
    
    parser.add_argument(
        '--no-clear', '--append',
        dest='clear_discovered',
        action='store_false',
        default=True,
        help='Do not clear discovered.txt at start, append to existing file instead (default: clear)'
    )
    
    args = parser.parse_args()
    
    # Set logging level based on verbose flag
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Parse comma-separated search strings
    search_strings = [s.strip() for s in args.search_strings.split(',') if s.strip()]
    if not search_strings:
        logger.error("At least one non-empty search string is required")
        sys.exit(1)
    
    # Determine scan mode: --list or --folders/default
    if args.list:
        # Scan from list file mode
        list_file_path = Path(args.list)
        if not list_file_path.exists():
            logger.error(f"List file does not exist: {list_file_path}")
            sys.exit(1)
        
        # Directory is optional when using --list, but still needed for initialization
        # Use current directory as default if not provided
        target_directory = args.directory if args.directory else os.getcwd()
        
        # Create searcher (target_folders not needed for list mode)
        searcher = SQLiteSearcher(target_directory, search_strings, None, max_workers=args.workers, clear_discovered=args.clear_discovered)
        
        try:
            searcher.scan_from_list(list_file_path)
            searcher.generate_report()
        except KeyboardInterrupt:
            logger.info("\nSearch interrupted by user")
            searcher.generate_report()
        except Exception as e:
            logger.error(f"Unexpected error during search: {e}")
            sys.exit(1)
    
    else:
        # Scan directory mode (default or with --folders)
        if not args.directory:
            logger.error("Directory is required when not using --list option")
            parser.print_help()
            sys.exit(1)
        
        if not os.path.exists(args.directory):
            logger.error(f"Directory does not exist: {args.directory}")
            sys.exit(1)
        
        # Parse comma-separated folders if provided
        target_folders = None
        if args.folders:
            target_folders = [f.strip() for f in args.folders.split(',') if f.strip()]
        
        # Create searcher and run scan
        searcher = SQLiteSearcher(args.directory, search_strings, target_folders, max_workers=args.workers, clear_discovered=args.clear_discovered)
        
        try:
            searcher.scan_directory()
            searcher.generate_report()
        except KeyboardInterrupt:
            logger.info("\nSearch interrupted by user")
            searcher.generate_report()
        except Exception as e:
            logger.error(f"Unexpected error during search: {e}")
            sys.exit(1)


if __name__ == "__main__":
    main()
