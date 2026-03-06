"""
Hero browser automation wrapper for Python.

This module provides a Python interface to the Ulixee Hero browser,
which is implemented in Node.js. It communicates with Hero via subprocess
and JSON messaging.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

from web_crawler.auth.lmsa import _log


class HeroClient:
    """Python client for Ulixee Hero browser automation.

    Hero is a Node.js-based headless browser optimized for web scraping
    and Akamai bypass. This client wraps the hero_login.js script and
    provides a Python interface.

    Usage::

        client = HeroClient()
        if not client.is_available():
            print("Hero not available - run: npm install")
            return

        wust = client.login("user@example.com", "password", "https://...")
        if wust:
            print(f"Login successful: {wust}")
    """

    def __init__(self, script_dir: Optional[str] = None) -> None:
        """Initialize Hero client.

        Args:
            script_dir: Directory containing hero_login.js.
                       Defaults to repository root.
        """
        if script_dir is None:
            # Default to repository root (where hero_login.js lives)
            script_dir = Path(__file__).parent.parent.parent
        self.script_dir = Path(script_dir)
        self.hero_script = self.script_dir / "hero_login.js"

    def is_available(self) -> bool:
        """Check if Hero is available and properly installed.

        Returns:
            True if Node.js and Hero are installed, False otherwise.
        """
        # Check if hero_login.js exists
        if not self.hero_script.exists():
            _log("[Hero] hero_login.js not found")
            return False

        # Check if Node.js is available
        try:
            result = subprocess.run(
                ["node", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                _log("[Hero] Node.js not found in PATH")
                return False
        except (subprocess.SubprocessError, FileNotFoundError):
            _log("[Hero] Node.js not installed or not in PATH")
            return False

        # Check if @ulixee/hero is installed
        node_modules = self.script_dir / "node_modules" / "@ulixee" / "hero"
        if not node_modules.exists():
            _log("[Hero] @ulixee/hero not installed - run: npm install")
            return False

        return True

    def login(
        self,
        email: str,
        password: str,
        login_url: str,
        timeout: int = 120,
    ) -> Optional[str]:
        """Perform login via Hero and return WUST token.

        Args:
            email: Lenovo ID email address
            password: Lenovo ID password
            login_url: Full login URL (from getApiInfo.jhtml)
            timeout: Maximum time to wait for login (seconds)

        Returns:
            WUST token on success, None on failure
        """
        if not self.is_available():
            _log("[Hero] Hero not available - cannot proceed")
            return None

        _log(f"[Hero] Launching Hero login script...")
        _log(f"[Hero] Email: {email}")
        _log(f"[Hero] Login URL: {login_url[:80]}...")

        try:
            # Run hero_login.js with arguments
            result = subprocess.run(
                [
                    "node",
                    str(self.hero_script),
                    email,
                    password,
                    login_url,
                ],
                cwd=str(self.script_dir),
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            # Parse stdout (should contain JSON response)
            stdout_lines = result.stdout.strip().split('\n')
            # The last line should be the JSON result
            json_output = stdout_lines[-1] if stdout_lines else ""

            # Log stderr (diagnostic messages from Hero)
            if result.stderr:
                for line in result.stderr.strip().split('\n'):
                    if line:
                        _log(f"[Hero] {line}")

            if not json_output:
                _log("[Hero] No JSON output from Hero script")
                return None

            try:
                response = json.loads(json_output)
            except json.JSONDecodeError as e:
                _log(f"[Hero] Invalid JSON response: {json_output[:200]}")
                _log(f"[Hero] JSON decode error: {e}")
                return None

            if response.get("success"):
                wust = response.get("wust")
                if wust:
                    _log("[Hero] ✓ WUST token obtained via Hero")
                    return wust
                else:
                    _log("[Hero] Success response but no WUST token")
                    return None
            else:
                error = response.get("error", "Unknown error")
                _log(f"[Hero] Login failed: {error}")
                return None

        except subprocess.TimeoutExpired:
            _log(f"[Hero] Login timeout after {timeout}s")
            return None
        except subprocess.SubprocessError as e:
            _log(f"[Hero] Subprocess error: {e}")
            return None
        except Exception as e:
            _log(f"[Hero] Unexpected error: {e}")
            return None


def install_hero() -> bool:
    """Install Hero npm package.

    Returns:
        True if installation succeeded, False otherwise
    """
    script_dir = Path(__file__).parent.parent.parent

    _log("[Hero] Installing @ulixee/hero via npm...")

    try:
        # Check if npm is available
        result = subprocess.run(
            ["npm", "--version"],
            capture_output=True,
            timeout=5,
        )
        if result.returncode != 0:
            _log("[Hero] npm not found - please install Node.js and npm")
            return False

        # Run npm install
        result = subprocess.run(
            ["npm", "install"],
            cwd=str(script_dir),
            capture_output=True,
            text=True,
            timeout=300,  # 5 minutes
        )

        if result.returncode == 0:
            _log("[Hero] ✓ Hero installed successfully")
            return True
        else:
            _log(f"[Hero] npm install failed:\n{result.stderr}")
            return False

    except (subprocess.SubprocessError, FileNotFoundError) as e:
        _log(f"[Hero] Installation failed: {e}")
        return False
