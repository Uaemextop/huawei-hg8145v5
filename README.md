# Huawei HG8145V5 Router Web Crawler

A Python web crawler designed to extract and backup the complete web interface of the Huawei HG8145V5 router. The crawler authenticates with the router, navigates through administration pages, and downloads all accessible content (HTML, JavaScript, CSS, images, ASP files, etc.) while maintaining the original directory structure for offline analysis.

## Features

- **Automatic Authentication**: Handles router login with CSRF token management
- **Comprehensive Crawling**: Discovers and downloads all accessible pages and resources
- **Structure Preservation**: Maintains original website directory structure
- **Resource Discovery**: Extracts links from HTML, CSS, and JavaScript files
- **Error Handling**: Includes retry logic and comprehensive error logging
- **Progress Tracking**: Logs all activities to both console and log file

## Requirements

- Python 3.7 or higher
- Windows/Linux/MacOS
- Network access to the router (default: 192.168.100.1)

## Installation

1. Clone this repository:
```bash
git clone https://github.com/Uaemextop/huawei-hg8145v5.git
cd huawei-hg8145v5
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

Run the crawler with default settings:

```bash
python huawei_crawler.py
```

This will:
- Connect to http://192.168.100.1
- Login with default credentials (user: Mega_gpon, password: 796cce597901a5cf)
- Download all content to `router_backup` directory

### Advanced Usage

Customize the crawler with command-line arguments:

```bash
python huawei_crawler.py --url http://192.168.100.1 --username Mega_gpon --password 796cce597901a5cf --output my_backup
```

### Command-Line Arguments

- `--url`: Router base URL (default: http://192.168.100.1)
- `--username`: Login username (default: Mega_gpon)
- `--password`: Login password (default: 796cce597901a5cf)
- `--output`: Output directory for downloaded files (default: router_backup)

### Example

```bash
# Backup to a custom directory
python huawei_crawler.py --output backup_2024

# Use different credentials
python huawei_crawler.py --username admin --password mypassword

# Connect to a different IP address
python huawei_crawler.py --url http://192.168.1.1
```

## Output Structure

The crawler creates a directory structure that mirrors the router's web interface:

```
router_backup/
├── CRAWLER_INDEX.html        # Index of all downloaded files
├── index.asp                  # Main login page
├── Cuscss/                    # CSS files
│   ├── login.css
│   └── english/
│       └── frame.css
├── resource/                  # JavaScript resources
│   └── common/
│       ├── md5.js
│       ├── util.js
│       └── jquery.min.js
├── frameaspdes/               # Language resources
│   └── english/
│       └── ssmpdes.js
├── images/                    # Image files
└── crawler.log               # Execution log
```

## Logging

The crawler generates a `crawler.log` file in the current directory, containing:
- Login attempts and results
- URLs being crawled
- Files being downloaded
- Error messages and warnings
- Summary statistics

## How It Works

1. **Authentication**:
   - Requests CSRF token from `/asp/GetRandCount.asp`
   - Encodes password in Base64
   - Submits login credentials to `/login.cgi`

2. **Discovery**:
   - Starts with common router pages (index.asp, frame.asp, status.asp, etc.)
   - Parses HTML to extract all links and resource references
   - Follows links to discover additional pages

3. **Download**:
   - Downloads each discovered resource
   - Preserves directory structure
   - Handles both text and binary files appropriately

4. **Resource Extraction**:
   - Extracts URLs from HTML tags (a, link, script, img, iframe)
   - Parses CSS for url() references
   - Resolves relative URLs to absolute URLs

## Troubleshooting

### Connection Issues

If you cannot connect to the router:
- Verify the router IP address: `ping 192.168.100.1`
- Check if you're connected to the router's network
- Try accessing the web interface manually in a browser

### Login Failures

If login fails:
- Verify credentials are correct
- Check if the router interface has changed
- Review the `crawler.log` for specific error messages

### Incomplete Downloads

If some files are missing:
- Check `crawler.log` for failed downloads
- Verify you have sufficient disk space
- Ensure stable network connection

## Security Notes

- The crawler stores credentials in memory during execution
- Use caution when sharing log files as they may contain sensitive information
- Downloaded content may contain router configuration details
- This tool is intended for authorized use on your own equipment

## Default Credentials

- **Username**: Mega_gpon
- **Password**: 796cce597901a5cf

**Important**: Change default credentials after installation for security.

## License

This project is provided as-is for educational and backup purposes.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## Disclaimer

This tool is designed for legitimate backup and analysis purposes on equipment you own or have authorization to access. Unauthorized access to network devices is illegal.
