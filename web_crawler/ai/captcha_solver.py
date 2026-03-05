"""
AI-powered CAPTCHA solver using Playwright browser automation and the
GitHub Models vision API.

Adapted from `Auto_CAPTCHA_with_LLM <https://github.com/erichung9060/Auto_CAPTCHA_with_LLM>`_
(content.js flow) to run headlessly via Playwright instead of as a Chrome
extension.  The CAPTCHA recognition itself is delegated to
:class:`~web_crawler.ai.github_models.GitHubModelsClient` which mirrors
the extension's ``recognize_by_Gemini`` / ``recognize_by_CloudVision``
logic.

Strategy (mirrors the extension's ``recognizeAndFill`` flow)
------------------------------------------------------------
1. Open the target page in a Playwright browser.
2. Locate the CAPTCHA ``<img>`` (or ``<input type="image">``) element
   and the verification-code ``<input>`` field — the Python equivalent
   of the extension's ``getElementSelector`` + ``process()``.
3. Screenshot the CAPTCHA element and encode it as base64 — equivalent
   to the extension's ``getBase64Image`` (canvas draw → toDataURL).
4. Send the image to ``GitHubModelsClient.recognize_captcha`` with the
   chosen ``captchaType`` (numbersOnly / lettersOnly / auto).
5. Fill the verification code into the input field using Playwright's
   native value setter + dispatched events — matching the extension's
   ``nativeInputValueSetter.call`` + event dispatch pattern.
6. Click submit and verify success.
"""

import base64
from typing import Any, Optional

from web_crawler.utils.log import log

try:
    from playwright.sync_api import (
        Page,
        sync_playwright,
    )
    _PLAYWRIGHT_AVAILABLE = True
except ImportError:
    _PLAYWRIGHT_AVAILABLE = False

from web_crawler.ai.github_models import (
    CAPTCHA_TYPE_AUTO,
    GitHubModelsClient,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_MAX_SOLVE_ATTEMPTS = 3
_PAGE_LOAD_TIMEOUT_MS = 30_000
_CAPTCHA_WAIT_MS = 3_000

# CSS selectors — extended version of the extension's recording targets.
# The extension lets users click to select; here we auto-detect.
_CAPTCHA_IMAGE_SELECTORS = [
    # <img> elements
    "img[id*='captcha' i]",
    "img[class*='captcha' i]",
    "img[id*='verify' i]",
    "img[src*='captcha' i]",
    "img[src*='verify' i]",
    "img[alt*='captcha' i]",
    "img[alt*='verification' i]",
    "#captcha_img",
    ".captcha-image",
    ".verify-img",
    # <input type="image"> elements (supported by the original extension)
    "input[type='image'][src*='captcha' i]",
    "input[type='image'][id*='captcha' i]",
]

_CAPTCHA_INPUT_SELECTORS = [
    "input[id*='captcha' i]",
    "input[name*='captcha' i]",
    "input[id*='verify' i]",
    "input[name*='verify' i]",
    "input[id*='verification' i]",
    "input[placeholder*='captcha' i]",
    "input[placeholder*='verification' i]",
    "#captcha_input",
    ".captcha-input",
]

_SUBMIT_BUTTON_SELECTORS = [
    "button[type='submit']",
    "input[type='submit']",
    "button[id*='login' i]",
    "button[class*='login' i]",
    "#login_btn",
    ".login-btn",
    "button:has-text('Log in')",
    "button:has-text('Login')",
    "button:has-text('Sign in')",
    "button:has-text('Submit')",
]


class AICaptchaSolver:
    """Solve CAPTCHAs on web pages using AI vision + Playwright browser.

    Reproduces the ``Auto_CAPTCHA_with_LLM`` extension workflow in Python:
    detect CAPTCHA image → capture as base64 → send to LLM → fill input.

    Parameters
    ----------
    ai_client : GitHubModelsClient
        Pre-configured GitHub Models client with vision support.
    headless : bool
        Run the browser in headless mode (default ``True``).
    max_attempts : int
        Maximum CAPTCHA solve attempts before giving up.
    captcha_type : str
        Default CAPTCHA type: ``"numbersOnly"``, ``"lettersOnly"``, or
        ``"auto"`` (mirrors the extension's radio selection).
    """

    def __init__(
        self,
        ai_client: GitHubModelsClient,
        headless: bool = True,
        max_attempts: int = _MAX_SOLVE_ATTEMPTS,
        captcha_type: str = CAPTCHA_TYPE_AUTO,
    ) -> None:
        if not _PLAYWRIGHT_AVAILABLE:
            raise ImportError(
                "Playwright is required for AI CAPTCHA solving.  "
                "Install it with:  pip install playwright && "
                "playwright install chromium firefox"
            )
        self._ai = ai_client
        self._headless = headless
        self._max_attempts = max_attempts
        self._captcha_type = captcha_type

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def solve_login_captcha(
        self,
        url: str,
        *,
        username: str = "",
        password: str = "",
        username_selector: str = "",
        password_selector: str = "",
        captcha_img_selector: str = "",
        captcha_input_selector: str = "",
        captcha_type: str = "",
    ) -> dict[str, str] | None:
        """Open *url*, fill login credentials, solve the CAPTCHA, and
        return the session cookies on success.

        The ``captcha_img_selector`` and ``captcha_input_selector``
        parameters mirror the extension's recording feature: if provided,
        they are used directly instead of auto-detecting.

        Parameters
        ----------
        url : str
            The login page URL.
        username / password : str
            Optional credentials to fill before solving the CAPTCHA.
        username_selector / password_selector : str
            CSS selectors for the credential fields (auto-detected when
            not provided).
        captcha_img_selector / captcha_input_selector : str
            CSS selectors for the CAPTCHA image and input field.  When
            omitted, the solver auto-detects them.
        captcha_type : str
            Override the default CAPTCHA type for this solve.

        Returns
        -------
        dict[str, str] | None
            Cookie dictionary on success, ``None`` on failure.
        """
        ctype = captcha_type or self._captcha_type
        log.info("[AI-CAPTCHA] Opening login page: %s", url)

        with sync_playwright() as pw:
            # Try Firefox first — its TLS fingerprint is less likely to
            # be flagged by bot-detection systems like Akamai.
            try:
                browser = pw.firefox.launch(headless=self._headless)
                log.info("[AI-CAPTCHA] Using Firefox browser engine")
            except Exception:
                browser = pw.chromium.launch(
                    headless=self._headless,
                    args=["--disable-blink-features=AutomationControlled"],
                )
                log.info("[AI-CAPTCHA] Using Chromium browser engine "
                         "(Firefox unavailable)")
            context = browser.new_context()
            page = context.new_page()

            # Hide webdriver flag
            page.add_init_script(
                "Object.defineProperty(navigator, 'webdriver', "
                "{get: () => undefined})"
            )

            try:
                page.goto(url, wait_until="domcontentloaded",
                          timeout=_PAGE_LOAD_TIMEOUT_MS)
            except Exception as exc:
                log.error("[AI-CAPTCHA] Failed to load page: %s", exc)
                browser.close()
                return None

            page.wait_for_timeout(_CAPTCHA_WAIT_MS)

            # Early-exit when the page is clearly not a login/CAPTCHA page
            # (e.g. the Apache Tomcat default page at lsa.lenovo.com).
            if not captcha_img_selector and not username:
                has_captcha = self._find_element(
                    page, _CAPTCHA_IMAGE_SELECTORS,
                )
                has_login_form = self._find_element(page, [
                    "input[type='password']",
                    "form[action*='login' i]",
                    "form[action*='signin' i]",
                    "input[name*='captcha' i]",
                ])
                if not has_captcha and not has_login_form:
                    log.warning(
                        "[AI-CAPTCHA] Page has no CAPTCHA or login form — "
                        "skipping (not a login page)"
                    )
                    browser.close()
                    return None

            # Fill credentials if provided
            if username:
                self._fill_field(page, username, username_selector, [
                    "input[name*='user' i]",
                    "input[id*='user' i]",
                    "input[type='text']",
                    "input[name*='login' i]",
                    "input[name*='account' i]",
                    "input[id*='account' i]",
                ])
            if password:
                self._fill_field(page, password, password_selector, [
                    "input[type='password']",
                    "input[name*='pass' i]",
                    "input[id*='pass' i]",
                ])

            # Attempt to solve the CAPTCHA
            for attempt in range(1, self._max_attempts + 1):
                log.info(
                    "[AI-CAPTCHA] Solve attempt %d/%d",
                    attempt, self._max_attempts,
                )
                solved = self._attempt_solve(
                    page,
                    ctype,
                    captcha_img_selector,
                    captcha_input_selector,
                )
                if not solved:
                    log.warning(
                        "[AI-CAPTCHA] Could not detect/solve CAPTCHA "
                        "(attempt %d)", attempt,
                    )
                    self._try_refresh_captcha(page)
                    page.wait_for_timeout(_CAPTCHA_WAIT_MS)
                    continue

                # Click submit
                self._click_submit(page)
                page.wait_for_timeout(_CAPTCHA_WAIT_MS)

                # Check if login succeeded
                if self._is_login_success(page, url):
                    cookies = {
                        c["name"]: c["value"]
                        for c in context.cookies()
                    }
                    log.info(
                        "[AI-CAPTCHA] Login successful (%d cookies)",
                        len(cookies),
                    )
                    browser.close()
                    return cookies

                log.info("[AI-CAPTCHA] Login not yet confirmed, retrying …")

            log.warning(
                "[AI-CAPTCHA] Failed after %d attempts", self._max_attempts,
            )
            browser.close()
            return None

    def solve_captcha_on_page(
        self,
        page: "Page",
        captcha_type: str = "",
    ) -> Optional[str]:
        """Detect and solve a CAPTCHA on an already-open Playwright page.

        Returns the CAPTCHA solution string or ``None`` on failure.
        """
        ctype = captcha_type or self._captcha_type
        screenshot_b64 = self._capture_captcha_image(page)
        if not screenshot_b64:
            return None
        result = self._ai.recognize_captcha(screenshot_b64, ctype)
        if result.get("isSuccess"):
            code = result["verificationCode"]
            log.info("[AI-CAPTCHA] AI solution: %s", code)
            return code
        log.warning("[AI-CAPTCHA] Recognition failed: %s", result.get("error"))
        return None

    def extract_text_from_page(self, page: "Page") -> str:
        """Take a full-page screenshot and extract all visible text."""
        raw = page.screenshot(full_page=True)
        b64 = base64.b64encode(raw).decode("ascii")
        return self._ai.extract_text(image_base64=b64)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _attempt_solve(
        self,
        page: "Page",
        captcha_type: str,
        img_selector: str,
        input_selector: str,
    ) -> bool:
        """Try to solve the CAPTCHA on the current page.

        Mirrors the extension's ``recognizeAndFill`` function.
        """
        # 1. Capture the CAPTCHA image as base64 (≈ getBase64Image)
        screenshot_b64 = self._capture_captcha_image(page, img_selector)
        if not screenshot_b64:
            log.debug("[AI-CAPTCHA] No CAPTCHA element found, using full page")
            raw = page.screenshot()
            screenshot_b64 = base64.b64encode(raw).decode("ascii")

        # Skip trivially small images (< 300 chars base64, same guard as
        # the extension: ``if base64Image.length < 300``)
        if len(screenshot_b64) < 300:
            log.debug("[AI-CAPTCHA] Image base64 too small, skipping")
            return False

        # 2. Ask the AI model to solve it (≈ recognizeCaptcha)
        result = self._ai.recognize_captcha(screenshot_b64, captcha_type)
        if not result.get("isSuccess"):
            log.warning("[AI-CAPTCHA] Backend error: %s", result.get("error"))
            return False
        code = result["verificationCode"]
        log.info("[AI-CAPTCHA] AI returned solution: %s", code)

        # 3. Fill the solution (≈ nativeInputValueSetter + event dispatch)
        captcha_input = self._find_element(
            page,
            [input_selector] if input_selector else _CAPTCHA_INPUT_SELECTORS,
        )
        if not captcha_input:
            log.warning("[AI-CAPTCHA] No CAPTCHA input field found")
            return False

        # Use Playwright's fill (dispatches input/change events natively,
        # matching the extension's manual event dispatch).
        captcha_input.fill("")
        captcha_input.type(code, delay=50)
        # Dispatch extra events to trigger any framework listeners
        captcha_input.dispatch_event("input")
        captcha_input.dispatch_event("change")
        return True

    def _capture_captcha_image(
        self,
        page: "Page",
        selector: str = "",
    ) -> Optional[str]:
        """Locate the CAPTCHA image element and return a base64 screenshot.

        Mirrors the extension's ``getBase64Image`` canvas-capture.
        """
        selectors = [selector] if selector else _CAPTCHA_IMAGE_SELECTORS
        el = self._find_element(page, selectors)
        if not el:
            return None
        try:
            raw = el.screenshot()
            return base64.b64encode(raw).decode("ascii")
        except Exception as exc:
            log.debug("[AI-CAPTCHA] Screenshot failed: %s", exc)
            return None

    @staticmethod
    def _find_element(page: "Page", selectors: list[str]) -> Any:
        """Return the first visible element matching one of *selectors*.

        Mirrors the extension's ``getElementBySelector`` with fallback
        through multiple selectors.
        """
        for sel in selectors:
            if not sel:
                continue
            try:
                el = page.query_selector(sel)
                if el and el.is_visible():
                    return el
            except Exception:
                continue
        return None

    @staticmethod
    def _fill_field(
        page: "Page",
        value: str,
        explicit_selector: str,
        fallback_selectors: list[str],
    ) -> None:
        """Fill *value* into the first matching field."""
        selectors = [explicit_selector] if explicit_selector else fallback_selectors
        for sel in selectors:
            try:
                el = page.query_selector(sel)
                if el and el.is_visible():
                    el.fill(value)
                    return
            except Exception:
                continue

    @staticmethod
    def _click_submit(page: "Page") -> None:
        """Click the submit / login button."""
        for sel in _SUBMIT_BUTTON_SELECTORS:
            try:
                el = page.query_selector(sel)
                if el and el.is_visible():
                    el.click()
                    return
            except Exception:
                continue
        # Last resort: press Enter
        page.keyboard.press("Enter")

    @staticmethod
    def _try_refresh_captcha(page: "Page") -> None:
        """Click common CAPTCHA refresh buttons/links."""
        refresh_selectors = [
            "[id*='refresh' i]",
            "[class*='refresh' i]",
            "a:has-text('refresh')",
            "a:has-text('Refresh')",
            "[onclick*='captcha' i]",
        ]
        for sel in refresh_selectors:
            try:
                el = page.query_selector(sel)
                if el and el.is_visible():
                    el.click()
                    return
            except Exception:
                continue

    @staticmethod
    def _is_login_success(page: "Page", original_url: str) -> bool:
        """Heuristic check for whether the login succeeded.

        Uses URL path comparison (not naive string matching) to avoid
        false positives on URLs that contain 'login' in query params or
        as part of unrelated words.
        """
        import urllib.parse
        current = page.url
        if current != original_url:
            cur_path = urllib.parse.urlparse(current).path.lower()
            if "/login" not in cur_path and "/signin" not in cur_path:
                return True
        for sel in _CAPTCHA_IMAGE_SELECTORS[:3]:
            try:
                if page.query_selector(sel):
                    return False
            except Exception:
                continue
        return True
