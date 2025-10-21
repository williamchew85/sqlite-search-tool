# SQLite Database Search Tool

A powerful Python tool for searching strings within SQLite database files across directory structures. Perfect for digital forensics, data analysis, and database investigation tasks.

## Features

- **Multi-string Search**: Search for multiple strings simultaneously using comma-separated values
- **Recursive Directory Scanning**: Automatically discovers SQLite databases regardless of file extension
- **Case-Insensitive Search**: Finds matches regardless of case
- **Folder Filtering**: Target specific directories (e.g., Microsoft, Mozilla, Google folders)
- **Comprehensive Reporting**: Detailed output showing file paths, table names, columns, and matched content
- **Progress Tracking**: Real-time progress updates and statistics
- **Logging**: Full logging support with configurable verbosity
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

### Command Line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--folders` | `-f` | Comma-separated list of folders to target |
| `--verbose` | `-v` | Enable verbose logging with debug information |
| `--help` | `-h` | Show help message and exit |

## Output

The tool provides comprehensive output including:

### Console Output
- Real-time progress updates
- Found SQLite databases
- Match details with file paths, table names, and columns
- Summary statistics

### Log File
- Detailed logging saved to `sqlite_search.log`
- Timestamps for all operations
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

1. **File Discovery**: Recursively scans the target directory for files
2. **SQLite Detection**: Attempts to open each file as a SQLite database
3. **Table Enumeration**: Discovers all tables within each database
4. **Content Search**: Searches through all columns in all tables
5. **Match Reporting**: Records matches with full context information

### Performance Considerations

- **File Size Limit**: Automatically skips files larger than 100MB
- **Memory Efficient**: Processes databases one at a time
- **Progress Tracking**: Updates every 1000 files processed
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
- Processing statistics
- Performance metrics

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