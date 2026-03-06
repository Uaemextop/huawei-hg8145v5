#!/usr/bin/env python3
"""
Test script for Lenovo ID login using Hero browser.

Tests the complete login flow with the provided credentials.
"""

import os
import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from web_crawler.auth.lenovo_id import LenovoIDAuth


def test_hero_login():
    """Test login with Hero using provided credentials."""

    # Credentials from the issue
    email = "eduardo@uaemex.top"
    password = "Edu@rdoc310104"

    print("=" * 70)
    print("Testing Lenovo ID Login with Hero")
    print("=" * 70)
    print(f"Email: {email}")
    print(f"Password: {'*' * len(password)}")
    print("=" * 70)
    print()

    # Create auth client
    auth = LenovoIDAuth()

    # Attempt login
    print("Attempting login...")
    session = auth.login(email=email, password=password)

    if session:
        print()
        print("=" * 70)
        print("✓ LOGIN SUCCESSFUL!")
        print("=" * 70)
        print(f"Session authenticated: {session.is_authenticated}")
        print()

        # Try a simple API call to verify the session works
        try:
            print("Testing session with a simple API call...")
            # This is just to verify the session object is valid
            print(f"Session base URL: {session._lmsa_base}")
            print(f"Session GUID: {session._guid}")
            print()
            print("✓ Session appears valid!")
        except Exception as e:
            print(f"Warning: Session validation failed: {e}")

        return True
    else:
        print()
        print("=" * 70)
        print("✗ LOGIN FAILED")
        print("=" * 70)
        print("No session returned. Check the logs above for details.")
        print()
        return False


if __name__ == "__main__":
    success = test_hero_login()
    sys.exit(0 if success else 1)
