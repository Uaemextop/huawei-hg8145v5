# Motorola Firmware Downloader

A professional, modular Python system for downloading Motorola firmware files with JWT authentication, concurrent downloads, and an interactive CLI interface.

## Features

- **JWT Authentication**: Secure authentication with Motorola servers using JWT tokens
- **Automatic Token Refresh**: Automatically refreshes tokens before expiration
- **Concurrent Downloads**: Download multiple files simultaneously (configurable 1-5 workers)
- **Search Engine**: Search for firmware by model, version, region with filtering
- **Interactive CLI**: User-friendly menu-driven interface
- **Progress Tracking**: Real-time download progress and status
- **Retry Logic**: Automatic retry with exponential backoff for failed operations
- **Configuration Management**: Centralized config.ini file
- **Secure Encryption**: AES-256 encryption for sensitive data
- **Comprehensive Logging**: Rotating log files with configurable levels

## Requirements

- Python 3.10+
- Dependencies listed in requirements.txt

## Installation

1. Install dependencies:

```bash
pip install -r motorola_downloader/requirements.txt
```

2. Create configuration file:

```bash
cp motorola_downloader/config.ini.template motorola_downloader/config.ini
```

3. Edit `config.ini` and fill in your credentials:
   - Set your GUID (UUID format)
   - Configure download directory
   - Adjust concurrent download limit
   - Set other preferences

## Usage

### Interactive CLI Mode

Run the interactive CLI:

```bash
python -m motorola_downloader
```

Or:

```bash
python motorola_downloader/main.py
```

### Main Menu Options

1. **Search for firmware**
   - Search by model name or version
   - Filter by content type (Firmware, ROM, Tools)
   - View detailed search results

2. **Download firmware**
   - Select from search results
   - Download single or multiple files
   - Track download progress
   - Automatic retry on failures

3. **Configuration**
   - View current configuration
   - Update max concurrent downloads
   - Modify settings

4. **Session information**
   - View session status
   - Check authentication state
   - See session duration

5. **Exit**
   - Clean shutdown with proper cleanup

## Configuration

The `config.ini` file contains all settings:

### [motorola_server]
- `base_url`: Motorola API base URL (HTTPS required)
- `guid`: Device GUID for authentication
- `jwt_token`: JWT token (auto-updated)
- `refresh_token`: Refresh token (auto-updated)

### [download]
- `output_directory`: Where to save downloaded files
- `max_concurrent_downloads`: Number of concurrent downloads (1-5)
- `timeout`: Request timeout in seconds
- `verify_ssl`: Whether to verify SSL certificates

### [search]
- `default_limit`: Maximum search results to return
- `default_region`: Default region filter
- `include_beta`: Include beta versions in results

### [logging]
- `log_level`: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `log_file`: Log file name
- `log_dir`: Log directory
- `max_log_size`: Maximum log file size before rotation
- `backup_count`: Number of backup log files to keep

### [authentication]
- `auto_refresh`: Automatically refresh expiring tokens
- `refresh_threshold`: Seconds before expiration to trigger refresh

## Project Structure

```
motorola_downloader/
├── __init__.py              # Package initialization
├── __main__.py              # Entry point for python -m
├── main.py                  # Alternative entry point
├── config.ini.template      # Configuration template
├── requirements.txt         # Python dependencies
├── utils/                   # Utility modules
│   ├── __init__.py
│   ├── logger.py            # Centralized logging
│   ├── validators.py        # Input validation
│   └── encryption.py        # Encryption utilities
├── core/                    # Core functionality
│   ├── __init__.py
│   ├── settings.py          # Configuration management
│   ├── http_client.py       # HTTP client with retry logic
│   ├── authenticator.py     # JWT authentication
│   ├── session_manager.py   # Session lifecycle management
│   ├── download_manager.py  # Concurrent download manager
│   └── search_engine.py     # Firmware search engine
└── cli/                     # Command-line interface
    ├── __init__.py
    └── main.py              # Interactive CLI

logs/                        # Log files (auto-created)
downloads/                   # Downloaded files (auto-created)
```

## Code Quality

All code follows professional Python standards:

- **Type Hints**: 100% type annotation coverage
- **Docstrings**: Google-style docstrings for all functions
- **Logging**: Comprehensive logging at appropriate levels
- **Error Handling**: Robust exception handling
- **Validation**: Input validation for all user data
- **Security**: HTTPS-only connections, credential encryption

## Authentication Flow

1. Load existing JWT token from config.ini (if available)
2. Validate token expiration
3. If expired, attempt refresh using refresh_token
4. If refresh fails or no token exists, prompt for password
5. Authenticate with GUID and password
6. Store new tokens in config.ini
7. Auto-refresh before expiration (configurable threshold)

## Download Flow

1. Search for firmware using model/version query
2. Filter and rank results by relevance
3. User selects files to download
4. Download manager creates concurrent tasks
5. Each file downloaded with retry logic
6. Progress tracked and displayed in real-time
7. Summary report on completion

## Security Features

- **HTTPS Only**: All connections use HTTPS
- **JWT Tokens**: Secure authentication tokens
- **No Hardcoded Credentials**: All credentials in config.ini
- **Token Hiding**: Sensitive values hidden in display
- **Input Validation**: All user inputs validated
- **AES-256 Encryption**: For encrypting sensitive data
- **PBKDF2 Password Hashing**: Industry-standard password hashing

## Error Handling

- **Automatic Retries**: Exponential backoff (1s, 2s, 4s)
- **Maximum Retries**: 3 attempts for network operations
- **Graceful Degradation**: Continue on non-fatal errors
- **Detailed Logging**: All errors logged with context
- **User-Friendly Messages**: Clear error messages in CLI

## Logging

Logs are stored in the `logs/` directory with automatic rotation:

- **Rotating Files**: Max 10MB per file
- **Backup Count**: Keep 5 backup files
- **Dual Output**: Both file and console logging
- **Configurable Levels**: Adjust verbosity in config.ini
- **Structured Format**: Timestamp, module, level, message

## Best Practices

1. **Never commit config.ini** with credentials to version control
2. **Keep JWT tokens secure** - they provide full API access
3. **Use appropriate concurrent limits** to avoid overwhelming servers
4. **Monitor logs** for errors and warnings
5. **Backup downloaded files** before cleaning download directory
6. **Update configuration** using the CLI config menu
7. **Respect server rate limits** with appropriate delays

## Troubleshooting

### Configuration Not Found
- Ensure `config.ini` exists (copy from `config.ini.template`)
- Check file permissions

### Authentication Failures
- Verify GUID format is correct (UUID)
- Check credentials
- Ensure base_url is accessible
- Review logs for detailed error messages

### Download Failures
- Check internet connection
- Verify SSL certificates (or disable verify_ssl for testing)
- Ensure sufficient disk space
- Check file permissions in output directory
- Review timeout settings

### Token Expiration
- Enable auto_refresh in config.ini
- Adjust refresh_threshold if needed
- Check system clock is accurate

## License

This project is provided as-is for educational and legitimate use only.

## Disclaimer

This tool is for downloading firmware for devices you own. Respect Motorola's terms of service and download policies. The authors are not responsible for misuse of this software.
