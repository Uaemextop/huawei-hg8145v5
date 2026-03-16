"""Extract Google Drive and cloud storage links from pages."""
import re
from web_crawler.extraction.base import BaseExtractor

_CLOUD_PATTERNS = [
    # Google Drive
    re.compile(r'https?://drive\.google\.com/(?:file/d/|open\?id=|uc\?[^"\'>\s]*id=|drive/folders/)[a-zA-Z0-9_-]+[^"\'>\s]*', re.I),
    # Google Docs / Sheets / Slides / Forms
    re.compile(r'https?://docs\.google\.com/(?:document|spreadsheets|presentation|forms)/d/[a-zA-Z0-9_-]+[^"\'>\s]*', re.I),
    # MEGA
    re.compile(r'https?://mega\.(?:nz|co\.nz)/(?:file|folder)/[^"\'>\s]+', re.I),
    # MediaFire
    re.compile(r'https?://(?:www\.)?mediafire\.com/(?:file|download)/[a-zA-Z0-9]+[^"\'>\s]*', re.I),
    # OneDrive: short links
    re.compile(r'https?://1drv\.ms/[a-zA-Z0-9]/[^"\'>\s]+', re.I),
    # OneDrive: full links (onedrive.live.com)
    re.compile(r'https?://onedrive\.live\.com/[^"\'>\s]+', re.I),
    # OneDrive / SharePoint shared links
    re.compile(r'https?://[a-zA-Z0-9_-]+\.sharepoint\.com/[^"\'>\s]*', re.I),
    # Dropbox: /s/, /sh/, /scl/fi/, /scl/fo/ patterns
    re.compile(r'https?://(?:www\.)?dropbox\.com/(?:s(?:h|cl)?|scl/f[io])/[^"\'>\s]+', re.I),
    # Dropbox: dl.dropboxusercontent.com direct download links
    re.compile(r'https?://dl\.dropboxusercontent\.com/[^"\'>\s]+', re.I),
]

class GoogleDriveExtractor(BaseExtractor):
    name = "google_drive"
    def can_handle(self, content_type, url):
        ct = content_type.split(";")[0].strip().lower()
        return ct in ("text/html", "application/xhtml+xml", "application/javascript", "text/javascript")
    def extract(self, content, url, base):
        found = set()
        for pat in _CLOUD_PATTERNS:
            for m in pat.finditer(content):
                found.add(m.group(0))
        return found

def extract_cloud_links(content):
    """Extract all cloud storage links from content."""
    found = set()
    for pat in _CLOUD_PATTERNS:
        for m in pat.finditer(content):
            found.add(m.group(0))
    return found
