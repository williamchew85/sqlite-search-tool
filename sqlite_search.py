#!/usr/bin/env python3
"""
SQLite Database Search Tool

This script recursively searches through a directory for SQLite database files
(regardless of file extension) and searches for one or more strings case-insensitively.

Usage:
    python sqlite_search.py <target_directory> <comma_separated_search_strings>

Example:
    python sqlite_search.py "C:\\Investigation\\a.smith\\AppData" "zaffrevelox"
    python sqlite_search.py "C:\\Investigation\\a.smith\\AppData" "zaffrevelox,password,email"
    python3 sqlite_search.py "/mnt/c/Investigation/a.smith/AppData" "zaffrevelox,13221442.hta,pfusioncaptcha.com,news.axonbyte.org,captcha_privacy.epub,cmd.exe /c for /r" --folders Microsoft,Mozilla,Google
"""

import os
import sys
import sqlite3
import argparse
from pathlib import Path
from typing import List, Tuple, Optional
import logging

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
    
    def __init__(self, target_directory: str, search_strings: List[str], target_folders: List[str] = None):
        self.target_directory = Path(target_directory)
        self.search_strings = [s.lower() for s in search_strings]  # Store as lowercase for case-insensitive search
        self.target_folders = target_folders or []  # List of specific folders to search in
        self.found_matches = []
        self.processed_files = 0
        self.sqlite_files_found = 0
        
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
            if file_path.stat().st_size < 96:
                return False
                
            # Try to open as SQLite database
            with sqlite3.connect(str(file_path)) as conn:
                # Try to execute a simple query to verify it's a valid SQLite DB
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' LIMIT 1")
                cursor.fetchone()
                return True
                
        except (sqlite3.DatabaseError, sqlite3.Error, OSError, IOError):
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
    
    def scan_directory(self) -> None:
        """
        Recursively scan the target directory for SQLite files and search for the target string.
        """
        logger.info(f"Starting scan of directory: {self.target_directory}")
        search_strings_quoted = ', '.join([f"'{s}'" for s in self.search_strings])
        logger.info(f"Searching for strings: {search_strings_quoted} (case-insensitive)")
        
        if self.target_folders:
            logger.info(f"Targeting specific folders: {', '.join(self.target_folders)}")
        
        if not self.target_directory.exists():
            logger.error(f"Target directory does not exist: {self.target_directory}")
            return
            
        # Walk through all files in the directory tree
        for root, dirs, files in os.walk(self.target_directory):
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
                    if file_path.stat().st_size > 100 * 1024 * 1024:  # 100MB
                        logger.debug(f"Skipping large file: {file_path}")
                        continue
                except OSError:
                    continue
                
                # Check if file is a SQLite database
                if self.is_sqlite_file(file_path):
                    self.sqlite_files_found += 1
                    logger.info(f"Found SQLite database: {file_path}")
                    
                    # Search for the target string in this database
                    matches = self.search_in_database(file_path)
                    
                    if matches:
                        logger.info(f"Found {len(matches)} matches in {file_path}")
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
                
                # Progress indicator
                if self.processed_files % 1000 == 0:
                    logger.info(f"Processed {self.processed_files} files, found {self.sqlite_files_found} SQLite databases")
    
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
        print(f"Total Matches Found: {len(self.found_matches)}")
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
        """
    )
    
    parser.add_argument(
        'directory',
        help='Target directory to search in'
    )
    
    parser.add_argument(
        'search_strings',
        help='Comma-separated strings to search for (case-insensitive)'
    )
    
    parser.add_argument(
        '--folders', '-f',
        help='Comma-separated folders to target (e.g., Microsoft,Mozilla,Google)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Set logging level based on verbose flag
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate arguments
    if not os.path.exists(args.directory):
        logger.error(f"Directory does not exist: {args.directory}")
        sys.exit(1)
    
    # Parse comma-separated search strings
    search_strings = [s.strip() for s in args.search_strings.split(',') if s.strip()]
    if not search_strings:
        logger.error("At least one non-empty search string is required")
        sys.exit(1)
    
    # Parse comma-separated folders if provided
    target_folders = None
    if args.folders:
        target_folders = [f.strip() for f in args.folders.split(',') if f.strip()]
    
    # Create searcher and run scan
    searcher = SQLiteSearcher(args.directory, search_strings, target_folders)
    
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
