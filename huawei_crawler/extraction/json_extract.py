"""
JSON path extraction.
"""

import json

from huawei_crawler.utils.url import normalise_url


def extract_json_paths(text: str, page_url: str, base: str) -> set[str]:
    """
    Parse JSON responses and extract string values that look like URL paths.
    """
    found: set[str] = set()
    try:
        obj = json.loads(text)
        queue = [obj]
        while queue:
            item = queue.pop()
            if isinstance(item, dict):
                queue.extend(item.values())
            elif isinstance(item, list):
                queue.extend(item)
            elif isinstance(item, str) and item.startswith("/"):
                n = normalise_url(item, page_url, base)
                if n:
                    found.add(n)
    except (json.JSONDecodeError, ValueError):
        pass
    return found
