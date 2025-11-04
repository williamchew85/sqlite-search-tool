# SQLite Database Search Tool

A powerful Python tool for searching strings within SQLite database files across directory structures. Perfect for digital forensics, data analysis, and database investigation tasks.

## Features

- **Multi-string Search**: Search for multiple strings simultaneously using comma-separated values
- **Concurrent Processing**: Parallel processing of multiple SQLite databases using configurable worker threads
- **Recursive Directory Scanning**: Automatically discovers SQLite databases regardless of file extension
- **List File Support**: Scan specific SQLite files from a list file (e.g., `discovered.txt`)
- **Discovered File Tracking**: Automatically saves all discovered SQLite database paths to `discovered.txt`
- **Append Mode**: Option to preserve and append to existing `discovered.txt` instead of clearing it
- **Case-Insensitive Search**: Finds matches regardless of case
- **Folder Filtering**: Target specific directories (e.g., Microsoft, Mozilla, Google folders)
- **Comprehensive Reporting**: Detailed output showing file paths, table names, columns, and matched content
- **Real-time Progress Tracking**: Live updates with cumulative match counts and SQLite database locations
- **Enhanced Logging**: Detailed logging with SQLite database locations, file sizes, and match statistics
- **Large File Handling**: Automatically skips files larger than 100MB to prevent memory issues

## Installation

### Prerequisites

- Python 3.6 or higher
- No additional dependencies required (uses only standard library)

### Setup

1. Clone or download the repository:
```bash
git clone <repository-url>
cd sqlite-search-tool
```

2. Make the script executable (optional):
```bash
chmod +x sqlite_search.py
```

## Usage

### Basic Syntax

```bash
python sqlite_search.py <target_directory> <comma_separated_search_strings> [options]
```

### Examples

#### Single String Search
```bash
python sqlite_search.py "C:\Investigation\a.smith\AppData" "zaffrevelox"
```

#### Multiple String Search
```bash
python sqlite_search.py "C:\Investigation\a.smith\AppData" "zaffrevelox,password,email"
```

#### With Folder Filtering
```bash
python sqlite_search.py "C:\Investigation\a.smith\AppData" "zaffrevelox" --folders Microsoft,Mozilla,Google
```

#### Verbose Output
```bash
python sqlite_search.py "C:\Users\User\AppData" "password" --verbose
```

#### Complex Search
```bash
python sqlite_search.py "/mnt/c/Investigation/a.smith/AppData" "zaffrevelox,13221442.hta,pfusioncaptcha.com,news.axonbyte.org,captcha_privacy.epub" --folders Microsoft,Mozilla,Google --verbose
```

#### Scan from List File
```bash
python sqlite_search.py "/mnt/c/Investigation/a.smith/AppData" "zaffrevelox" --list discovered.txt
```

#### Append to Existing Discovered File
```bash
python sqlite_search.py "/mnt/c/Investigation/a.smith/AppData" "zaffrevelox" --no-clear
```

#### With Custom Worker Count
```bash
python sqlite_search.py "/mnt/c/investigation/" "keyword" --workers 8
```

### Command Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--folders` | `-f` | Comma-separated list of folders to target (mutually exclusive with --list) |
| `--list` | `-l` | Path to file containing SQLite file paths to scan (one per line, e.g., discovered.txt). Mutually exclusive with --folders |
| `--workers` | `-w` | Number of concurrent workers for database processing (default: 4) |
| `--no-clear` | `--append` | Do not clear discovered.txt at start, append to existing file instead |
| `--verbose` | `-v` | Enable verbose logging with debug information |
| `--help` | `-h` | Show help message and exit |

## Output

The tool provides comprehensive output including:

### Console Output
- Real-time progress updates with cumulative match counts
- SQLite database locations with file sizes for every database found
- Match details with file paths, table names, and columns
- Summary statistics including total matches found

### Discovered File (`discovered.txt`)
- Automatically saves all discovered SQLite database paths in real-time
- One path per line with absolute file paths
- Can be used with `--list` option for targeted scanning
- Preserved with `--no-clear` option for cumulative tracking across runs

### Log File (`sqlite_search.log`)
- Detailed logging saved to `sqlite_search.log`
- Timestamps for all operations
- SQLite database locations and sizes
- Cumulative match counts in progress updates
- Error handling and warnings

### Final Report
```
================================================================================
SQLITE SEARCH REPORT
================================================================================
Target Directory: C:\Investigation\a.smith\AppData
Search Strings: 'zaffrevelox', 'password', 'email' (case-insensitive)
Total Files Processed: 1,234
SQLite Databases Found: 15
Total Matches Found: 3
Discovered SQLite files saved to: discovered.txt
================================================================================

MATCHES FOUND:
----------------------------------------

Match #1:
  File: C:\Investigation\a.smith\AppData\Local\Google\Chrome\User Data\Default\Login Data
  Table: logins
  Column: username_value
  Matched String: 'zaffrevelox'
  Content: zaffrevelox@example.com

Match #2:
  File: C:\Investigation\a.smith\AppData\Local\Google\Chrome\User Data\Default\Web Data
  Table: autofill
  Column: name
  Matched String: 'password'
  Content: password123
```

## Use Cases

### Digital Forensics
- Search for specific usernames, emails, or suspicious strings across browser databases
- Investigate application data for evidence
- Analyze user activity patterns

### Data Analysis
- Find specific data across multiple SQLite databases
- Extract information from application databases
- Perform bulk searches on database collections

### System Administration
- Locate specific data across application databases
- Audit database contents
- Clean up or migrate specific data

## Technical Details

### How It Works

1. **File Discovery**: Recursively scans the target directory for files (or reads from list file)
2. **Candidate Collection**: Filters files by size (>= 96 bytes) and collects candidates
3. **Concurrent Processing**: Uses ThreadPoolExecutor to process multiple SQLite databases in parallel
4. **SQLite Detection**: Attempts to open each file as a SQLite database and saves path to `discovered.txt`
5. **Table Enumeration**: Discovers all tables within each database
6. **Content Search**: Searches through all columns in all tables for target strings
7. **Match Reporting**: Records matches with full context information and cumulative totals

### Performance Considerations

- **Concurrent Processing**: Uses multiple worker threads (default: 4) for parallel database processing
- **File Size Limit**: Automatically skips files larger than 100MB
- **Memory Efficient**: Processes databases concurrently with thread-safe operations
- **Progress Tracking**: Updates every 1000 files processed with cumulative statistics
- **Real-time Updates**: `discovered.txt` is updated immediately as each SQLite database is found
- **Error Handling**: Continues processing even if individual databases fail

### Supported SQLite Features

- All SQLite database versions
- All table types (regular tables, views, etc.)
- All column types (TEXT, BLOB, INTEGER, etc.)
- Corrupted database handling

## Troubleshooting

### Common Issues

**Permission Denied**
```bash
# Run with appropriate permissions
sudo python sqlite_search.py "/path/to/directory" "search_string"
```

**Large Directory Performance**
```bash
# Use folder filtering to limit scope
python sqlite_search.py "/path/to/directory" "search_string" --folders Microsoft,Google

# Increase worker count for faster processing
python sqlite_search.py "/path/to/directory" "search_string" --workers 8
```

**Scan Specific Files from Previous Run**
```bash
# Use discovered.txt from previous scan to target specific files
python sqlite_search.py "/path/to/directory" "search_string" --list discovered.txt
```

**Cumulative Tracking Across Runs**
```bash
# Append to discovered.txt instead of clearing it
python sqlite_search.py "/path/to/directory" "search_string" --no-clear
```

**Verbose Debugging**
```bash
# Enable verbose mode for detailed output
python sqlite_search.py "/path/to/directory" "search_string" --verbose
```

### Log Analysis

Check the `sqlite_search.log` file for detailed information about:
- Files that couldn't be opened
- Database access errors
- Processing statistics with cumulative match counts
- SQLite database locations and file sizes
- Performance metrics and progress updates

Check the `discovered.txt` file for:
- All discovered SQLite database paths (one per line)
- Absolute file paths for all found databases
- Can be used as input for `--list` option

## Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is open source. Please check the license file for details.

## Changelog

### Version 2.0.0
- **Concurrent Processing**: Added multi-threaded processing with configurable worker count
- **Discovered File Tracking**: Automatically saves all SQLite database paths to `discovered.txt`
- **List File Support**: Added `--list` option to scan specific SQLite files from a list
- **Append Mode**: Added `--no-clear` / `--append` option to preserve `discovered.txt` across runs
- **Enhanced Logging**: 
  - SQLite database locations with file sizes displayed for every database found
  - Cumulative total matches count in progress updates
  - Real-time progress tracking with detailed statistics
- **Real-time Updates**: `discovered.txt` is updated immediately as databases are discovered
- **Improved Error Handling**: Better logging and error reporting throughout

### Version 1.0.0
- Initial release
- Multi-string search support
- Comma-separated input format
- Folder filtering
- Comprehensive reporting
- Logging support

## Support

For issues, questions, or contributions, please:
1. Check the troubleshooting section
2. Review the log files
3. Submit an issue on GitHub

---

**Note**: This tool is designed for legitimate investigative and administrative purposes. Always ensure you have proper authorization before scanning databases on systems you don't own.