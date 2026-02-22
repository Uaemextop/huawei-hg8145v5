# Quick Start Guide

## For Windows Users

1. **Install Python** (if not already installed)
   - Download from: https://www.python.org/downloads/
   - During installation, check "Add Python to PATH"

2. **Run the crawler**
   - Double-click `run_crawler.bat`
   - The script will automatically install dependencies
   - Wait for the crawling to complete

3. **View results**
   - Open the `router_backup` folder
   - Open `CRAWLER_INDEX.html` in your browser

## For Linux/Mac Users

1. **Open Terminal** in the project directory

2. **Make the script executable** (first time only):
   ```bash
   chmod +x run_crawler.sh
   ```

3. **Run the crawler**:
   ```bash
   ./run_crawler.sh
   ```

4. **View results**:
   ```bash
   cd router_backup
   open CRAWLER_INDEX.html  # Mac
   xdg-open CRAWLER_INDEX.html  # Linux
   ```

## Manual Installation

If you prefer to run manually:

```bash
# Install dependencies
pip install -r requirements.txt

# Run the crawler
python huawei_crawler.py

# Or with custom options
python huawei_crawler.py --url http://192.168.100.1 --username Mega_gpon --password 796cce597901a5cf --output my_backup
```

## Troubleshooting

### "Python is not recognized"
- Make sure Python is installed and added to PATH
- Try using `python3` instead of `python`

### "Cannot connect to router"
- Ensure you're connected to the router's network
- Verify the router IP address (try pinging 192.168.100.1)
- Check if the router's web interface is accessible in a browser

### "Login failed"
- Verify the username and password are correct
- Check if the router firmware has changed the login mechanism
- Review crawler.log for detailed error messages

### "Missing files"
- Some pages may require additional authentication
- Check crawler.log to see which URLs failed
- The router may have restricted access to certain pages

## Default Settings

- **Router IP**: 192.168.100.1
- **Username**: Mega_gpon
- **Password**: 796cce597901a5cf
- **Output Directory**: router_backup/

## What Gets Downloaded?

The crawler will attempt to download:
- All HTML/ASP pages
- JavaScript files (.js)
- CSS stylesheets (.css)
- Images (.jpg, .png, .gif, .ico, .svg)
- Configuration files
- Any other accessible resources

## Security Warning

This tool downloads the router's web interface which may contain:
- Configuration details
- Network information
- Credentials (stored or displayed)

Keep the downloaded files secure and do not share them publicly.

## Need Help?

Check the full README.md for detailed documentation.
Review crawler.log for execution details and errors.
