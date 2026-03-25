"""Git helper functions extracted from the crawler engine.

Provides utilities for Git LFS tracking, periodic commit/push of crawled
files, and saving HTTP response headers alongside downloaded content.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from crawl4ai.extensions.log_utils import log

if TYPE_CHECKING:
    import requests

    from crawl4ai.extensions.crawler.engine import Crawler

# Size threshold for automatic Git LFS tracking (50 MB).
LFS_SIZE_THRESHOLD: int = 50 * 1024 * 1024


def save_http_headers(local: Path, resp: requests.Response, url: str) -> None:
    """Save HTTP response headers as a ``.headers`` JSON file next to *local*."""
    headers_path = local.parent / (local.name + ".headers")
    header_data = {
        "url": url,
        "status_code": resp.status_code,
        "headers": dict(resp.headers),
    }
    headers_path.parent.mkdir(parents=True, exist_ok=True)
    headers_path.write_text(
        json.dumps(header_data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def git_lfs_track_large_files(crawler: Crawler, cwd: str) -> None:
    """Find files larger than :data:`LFS_SIZE_THRESHOLD` and track them with Git LFS."""
    out_dir = Path(cwd)
    tracked_any = False
    for f in out_dir.rglob("*"):
        if not f.is_file() or ".git" in f.parts:
            continue
        try:
            if f.stat().st_size > LFS_SIZE_THRESHOLD:
                rel = f.relative_to(out_dir)
                subprocess.run(
                    ["git", "lfs", "track", str(rel)],
                    cwd=cwd,
                    capture_output=True,
                    timeout=15,
                )
                log.debug(
                    "[GIT-LFS] Tracking %s (%.0f MB)",
                    rel,
                    f.stat().st_size / (1024 * 1024),
                )
                tracked_any = True
        except (OSError, subprocess.SubprocessError) as exc:
            log.warning("[GIT-LFS] Failed to track %s: %s", f, exc)
    if tracked_any:
        gitattr = out_dir / ".gitattributes"
        if gitattr.exists():
            subprocess.run(
                ["git", "add", ".gitattributes"],
                cwd=cwd,
                capture_output=True,
                timeout=15,
            )


def maybe_git_push(crawler: Crawler) -> None:
    """Commit and push progress every *git_push_every* saved files.

    When *upload_extensions* is set, only files matching those extensions
    (plus ``README.md``) are staged.  When debug mode is active,
    ``.headers`` files are included too.

    Files exceeding :data:`LFS_SIZE_THRESHOLD` are automatically tracked
    with Git LFS.
    """
    if crawler.git_push_every <= 0:
        return
    if crawler._stats["ok"] % crawler.git_push_every != 0:
        return

    # Update URL lists before pushing so they are included in the commit.
    crawler._write_url_list()
    crawler._write_video_url_list()

    ok: int = crawler._stats["ok"]
    log.info("[GIT] Pushing progress (%d files saved so far)…", ok)
    try:
        cwd = str(crawler.output_dir.resolve())
        # Track large files with Git LFS before staging.
        git_lfs_track_large_files(crawler, cwd)
        if crawler.upload_extensions:
            # Stage only files matching the upload extensions.
            subprocess.run(
                ["git", "add", "README.md"],
                cwd=cwd,
                capture_output=True,
                timeout=30,
            )
            # Stage URL list files when they exist.
            for txt in ("url_list.txt", "video_urls.txt"):
                if (crawler.output_dir / txt).exists():
                    subprocess.run(
                        ["git", "add", "--", txt],
                        cwd=cwd,
                        capture_output=True,
                        timeout=30,
                    )
            for ext in crawler.upload_extensions:
                args = ["git", "add", "--", f"*{ext}"]
                if crawler.debug:
                    args.append(f"*{ext}.headers")
                subprocess.run(
                    args,
                    cwd=cwd,
                    capture_output=True,
                    timeout=60,
                )
        else:
            subprocess.run(
                ["git", "add", "-A"],
                cwd=cwd,
                check=True,
                capture_output=True,
                timeout=60,
            )
        subprocess.run(
            ["git", "commit", "-m", f"Crawl progress: {ok} files saved"],
            cwd=cwd,
            check=True,
            capture_output=True,
            timeout=60,
        )
        subprocess.run(
            ["git", "push"],
            cwd=cwd,
            check=True,
            capture_output=True,
            timeout=300,
        )
        log.info("[GIT] Push OK (%d files)", ok)
    except subprocess.CalledProcessError as exc:
        msg = exc.stderr.decode(errors="replace").strip() if exc.stderr else str(exc)
        log.warning("[GIT] Push failed: %s", msg)
    except FileNotFoundError:
        log.warning("[GIT] git not found – disabling periodic push")
        crawler.git_push_every = 0
    except Exception as exc:
        log.warning("[GIT] Push error: %s", exc)
