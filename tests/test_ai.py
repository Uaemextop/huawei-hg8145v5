"""
Tests for the AI module (GitHub Models client and CAPTCHA solver).

Adapted from Auto_CAPTCHA_with_LLM patterns — tests verify the
client construction, prompt selection, verification code cleaning,
and captcha solver element detection logic without requiring a real
GitHub token or Playwright browser.
"""

import base64
import unittest
from unittest.mock import MagicMock, patch

from web_crawler.ai.github_models import (
    CAPTCHA_TYPE_AUTO,
    CAPTCHA_TYPE_LETTERS,
    CAPTCHA_TYPE_NUMBERS,
    GitHubModelsClient,
    _CAPTCHA_PROMPTS,
    _GITHUB_MODELS_ENDPOINT,
    _clean_verification_code,
)


# ------------------------------------------------------------------ #
# Verification code cleaning (mirrors extension's JS regex filter)
# ------------------------------------------------------------------ #

class TestCleanVerificationCode(unittest.TestCase):
    """Test _clean_verification_code — mirrors the extension's
    ``verificationCode.match(/[a-zA-Z0-9]+/g).join('')``."""

    def test_plain_alphanumeric(self):
        self.assertEqual(_clean_verification_code("AB12"), "AB12")

    def test_strips_spaces_and_punctuation(self):
        self.assertEqual(_clean_verification_code("  AB 12!  "), "AB12")

    def test_preserves_mixed_case(self):
        self.assertEqual(_clean_verification_code("aBcDeF"), "aBcDeF")

    def test_empty_string(self):
        self.assertEqual(_clean_verification_code(""), "")

    def test_only_symbols(self):
        self.assertEqual(_clean_verification_code("!!!@#$%"), "")

    def test_multiword_response(self):
        self.assertEqual(
            _clean_verification_code("The answer is: 4829"),
            "Theansweris4829",
        )

    def test_newlines_and_tabs(self):
        self.assertEqual(_clean_verification_code("AB\n12\tCD"), "AB12CD")


# ------------------------------------------------------------------ #
# CAPTCHA prompts
# ------------------------------------------------------------------ #

class TestCaptchaPrompts(unittest.TestCase):
    """Verify the CAPTCHA type prompts exist and match expectations."""

    def test_numbers_only_prompt(self):
        prompt = _CAPTCHA_PROMPTS[CAPTCHA_TYPE_NUMBERS]
        self.assertIn("numbers", prompt.lower())
        self.assertIn("digits", prompt.lower())

    def test_letters_only_prompt(self):
        prompt = _CAPTCHA_PROMPTS[CAPTCHA_TYPE_LETTERS]
        self.assertIn("letters", prompt.lower())

    def test_auto_prompt(self):
        prompt = _CAPTCHA_PROMPTS[CAPTCHA_TYPE_AUTO]
        self.assertIn("digits", prompt.lower())
        self.assertIn("words", prompt.lower())

    def test_all_types_present(self):
        self.assertIn(CAPTCHA_TYPE_NUMBERS, _CAPTCHA_PROMPTS)
        self.assertIn(CAPTCHA_TYPE_LETTERS, _CAPTCHA_PROMPTS)
        self.assertIn(CAPTCHA_TYPE_AUTO, _CAPTCHA_PROMPTS)


# ------------------------------------------------------------------ #
# GitHubModelsClient construction
# ------------------------------------------------------------------ #

class TestGitHubModelsClient(unittest.TestCase):
    """Test client construction and configuration."""

    def test_raises_without_token(self):
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(ValueError):
                GitHubModelsClient(token="")

    @patch("web_crawler.ai.github_models._OPENAI_AVAILABLE", True)
    def test_construction_with_explicit_token(self):
        with patch("web_crawler.ai.github_models.OpenAI"):
            client = GitHubModelsClient(token="ghp_test123")
            self.assertEqual(client.model, "openai/gpt-4o")

    @patch("web_crawler.ai.github_models._OPENAI_AVAILABLE", True)
    def test_custom_model(self):
        with patch("web_crawler.ai.github_models.OpenAI"):
            client = GitHubModelsClient(
                token="ghp_test123",
                model="openai/gpt-4o-mini",
            )
            self.assertEqual(client.model, "openai/gpt-4o-mini")

    @patch("web_crawler.ai.github_models._OPENAI_AVAILABLE", True)
    def test_endpoint_default(self):
        with patch("web_crawler.ai.github_models.OpenAI"):
            client = GitHubModelsClient(token="ghp_test123")
            self.assertEqual(client._endpoint, _GITHUB_MODELS_ENDPOINT)

    @patch("web_crawler.ai.github_models._OPENAI_AVAILABLE", True)
    def test_custom_endpoint(self):
        with patch("web_crawler.ai.github_models.OpenAI"):
            client = GitHubModelsClient(
                token="ghp_test123",
                endpoint="https://custom.endpoint.com",
            )
            self.assertEqual(client._endpoint, "https://custom.endpoint.com")

    def test_raises_without_openai_package(self):
        with patch("web_crawler.ai.github_models._OPENAI_AVAILABLE", False):
            with self.assertRaises(ImportError):
                GitHubModelsClient(token="ghp_test123")


# ------------------------------------------------------------------ #
# recognize_captcha response format
# ------------------------------------------------------------------ #

class TestRecognizeCaptcha(unittest.TestCase):
    """Test recognize_captcha return format matches the extension's
    ``{isSuccess, verificationCode/error}`` shape."""

    @patch("web_crawler.ai.github_models._OPENAI_AVAILABLE", True)
    def _make_client(self):
        with patch("web_crawler.ai.github_models.OpenAI"):
            return GitHubModelsClient(token="ghp_test123")

    def test_success_response_format(self):
        client = self._make_client()
        with patch.object(client, "chat", return_value="AB12"):
            result = client.recognize_captcha("dGVzdA==")
            self.assertTrue(result["isSuccess"])
            self.assertEqual(result["verificationCode"], "AB12")

    def test_failure_on_empty_response(self):
        client = self._make_client()
        with patch.object(client, "chat", return_value=""):
            result = client.recognize_captcha("dGVzdA==")
            self.assertFalse(result["isSuccess"])
            self.assertIn("error", result)

    def test_failure_on_exception(self):
        client = self._make_client()
        with patch.object(client, "chat", side_effect=Exception("API error")):
            result = client.recognize_captcha("dGVzdA==")
            self.assertFalse(result["isSuccess"])
            self.assertIn("API error", result["error"])

    def test_cleans_noisy_response(self):
        client = self._make_client()
        with patch.object(client, "chat", return_value="The code is: 4829!"):
            result = client.recognize_captcha("dGVzdA==")
            self.assertTrue(result["isSuccess"])
            self.assertEqual(result["verificationCode"], "Thecodeis4829")

    def test_numbers_only_type_uses_correct_prompt(self):
        client = self._make_client()
        with patch.object(client, "chat", return_value="1234") as mock_chat:
            client.recognize_captcha("dGVzdA==", CAPTCHA_TYPE_NUMBERS)
            call_args = mock_chat.call_args
            prompt = call_args[1].get("prompt", call_args[0][0] if call_args[0] else "")
            self.assertIn("numbers", prompt.lower())


# ------------------------------------------------------------------ #
# Image loading helpers
# ------------------------------------------------------------------ #

class TestImageHelpers(unittest.TestCase):
    """Test static image loading/fetching helpers."""

    @patch("web_crawler.ai.github_models._OPENAI_AVAILABLE", True)
    def test_load_image_file_not_found(self):
        with patch("web_crawler.ai.github_models.OpenAI"):
            with self.assertRaises(FileNotFoundError):
                GitHubModelsClient._load_image_file("/nonexistent/image.png")

    @patch("web_crawler.ai.github_models._OPENAI_AVAILABLE", True)
    def test_fetch_image_url_failure(self):
        with patch("web_crawler.ai.github_models._requests_lib") as mock_req:
            mock_req.get.side_effect = Exception("Network error")
            result = GitHubModelsClient._fetch_image_url("https://example.com/img.png")
            self.assertIsNone(result)


# ------------------------------------------------------------------ #
# solve_captcha_image convenience wrapper
# ------------------------------------------------------------------ #

class TestSolveCaptchaImage(unittest.TestCase):
    """Test the solve_captcha_image convenience method."""

    @patch("web_crawler.ai.github_models._OPENAI_AVAILABLE", True)
    def _make_client(self):
        with patch("web_crawler.ai.github_models.OpenAI"):
            return GitHubModelsClient(token="ghp_test123")

    def test_returns_code_on_success(self):
        client = self._make_client()
        with patch.object(
            client, "recognize_captcha",
            return_value={"isSuccess": True, "verificationCode": "XY99"},
        ):
            result = client.solve_captcha_image(image_base64="dGVzdA==")
            self.assertEqual(result, "XY99")

    def test_returns_empty_on_failure(self):
        client = self._make_client()
        with patch.object(
            client, "recognize_captcha",
            return_value={"isSuccess": False, "error": "fail"},
        ):
            result = client.solve_captcha_image(image_base64="dGVzdA==")
            self.assertEqual(result, "")

    def test_returns_empty_without_image(self):
        client = self._make_client()
        result = client.solve_captcha_image()
        self.assertEqual(result, "")


# ------------------------------------------------------------------ #
# LenovoIDAuth._solve_captcha_with_ai integration
# ------------------------------------------------------------------ #

class TestLenovoIDCaptchaIntegration(unittest.TestCase):
    """Test the AI CAPTCHA solver integration in LenovoIDAuth.

    Verifies that ``_solve_captcha_with_ai`` correctly delegates to the
    AI module and processes results without requiring real credentials
    or a real browser.
    """

    def _make_auth(self):
        from web_crawler.auth.lenovo_id import LenovoIDAuth
        return LenovoIDAuth(verify_ssl=False)

    def test_returns_none_without_github_token(self):
        """With no GITHUB_TOKEN the method should bail out gracefully."""
        auth = self._make_auth()
        page = MagicMock()
        captured: list[str] = []
        with patch.dict("os.environ", {}, clear=True):
            result = auth._solve_captcha_with_ai(page, captured)
        self.assertIsNone(result)

    @patch("web_crawler.ai.github_models._OPENAI_AVAILABLE", True)
    @patch("web_crawler.ai.github_models.OpenAI")
    def test_returns_wust_on_success(self, _mock_openai):
        """When AI solves the CAPTCHA and the page redirects, WUST is captured."""
        auth = self._make_auth()

        # Simulate a Playwright page object
        page = MagicMock()
        el = MagicMock()
        el.is_visible.return_value = True
        page.query_selector.return_value = el
        # After CAPTCHA submit, URL contains the WUST token
        page.url = "https://lsa.lenovo.com/Tips/lenovoIdSuccess.html?lenovoid.wust=FAKE_WUST_TOKEN"

        captured: list[str] = []

        with patch.dict("os.environ", {"GITHUB_TOKEN": "ghp_test123"}, clear=False):
            with patch("web_crawler.ai.captcha_solver.AICaptchaSolver") as MockSolver:
                mock_solver_instance = MagicMock()
                mock_solver_instance.solve_captcha_on_page.return_value = "AB12"
                MockSolver.return_value = mock_solver_instance

                result = auth._solve_captcha_with_ai(page, captured)

        self.assertEqual(result, "FAKE_WUST_TOKEN")

    @patch("web_crawler.ai.github_models._OPENAI_AVAILABLE", True)
    @patch("web_crawler.ai.github_models.OpenAI")
    def test_returns_none_when_ai_fails_all_attempts(self, _mock_openai):
        """If the AI solver fails all attempts, None is returned."""
        auth = self._make_auth()

        page = MagicMock()
        page.url = "https://passport.lenovo.com/login"

        captured: list[str] = []

        with patch.dict("os.environ", {"GITHUB_TOKEN": "ghp_test123"}, clear=False):
            with patch("web_crawler.ai.captcha_solver.AICaptchaSolver") as MockSolver:
                mock_solver_instance = MagicMock()
                # AI returns None for all attempts
                mock_solver_instance.solve_captcha_on_page.return_value = None
                MockSolver.return_value = mock_solver_instance

                result = auth._solve_captcha_with_ai(page, captured)

        self.assertIsNone(result)

    @patch("web_crawler.ai.github_models._OPENAI_AVAILABLE", True)
    @patch("web_crawler.ai.github_models.OpenAI")
    def test_reads_ai_model_from_env(self, mock_openai):
        """AI_MODEL env var is respected for model selection."""
        auth = self._make_auth()

        page = MagicMock()
        page.url = "https://passport.lenovo.com/login"
        captured: list[str] = []

        with patch.dict("os.environ", {
            "GITHUB_TOKEN": "ghp_test123",
            "AI_MODEL": "openai/gpt-4o-mini",
        }, clear=False):
            with patch("web_crawler.ai.captcha_solver.AICaptchaSolver") as MockSolver:
                mock_solver_instance = MagicMock()
                mock_solver_instance.solve_captcha_on_page.return_value = None
                MockSolver.return_value = mock_solver_instance

                with patch(
                    "web_crawler.ai.github_models.GitHubModelsClient",
                ) as MockClient:
                    # Prevent actual API calls
                    MockClient.return_value = MagicMock()

                    auth._solve_captcha_with_ai(page, captured)

                    # Verify the model was passed
                    MockClient.assert_called_once()
                    call_kwargs = MockClient.call_args
                    self.assertEqual(
                        call_kwargs.kwargs.get("model"),
                        "openai/gpt-4o-mini",
                    )

    @patch("web_crawler.ai.github_models._OPENAI_AVAILABLE", True)
    @patch("web_crawler.ai.github_models.OpenAI")
    def test_wust_from_captured_url(self, _mock_openai):
        """WUST is detected from the captured navigation URL list."""
        auth = self._make_auth()

        page = MagicMock()
        el = MagicMock()
        el.is_visible.return_value = True
        page.query_selector.return_value = el
        page.url = "https://passport.lenovo.com/login"  # No WUST in page.url

        # WUST was captured in a navigation event
        captured = [
            "https://lsa.lenovo.com/Tips/lenovoIdSuccess.html?lenovoid.wust=CAPTURED_WUST"
        ]

        with patch.dict("os.environ", {"GITHUB_TOKEN": "ghp_test123"}, clear=False):
            with patch("web_crawler.ai.captcha_solver.AICaptchaSolver") as MockSolver:
                mock_solver_instance = MagicMock()
                mock_solver_instance.solve_captcha_on_page.return_value = "1234"
                MockSolver.return_value = mock_solver_instance

                result = auth._solve_captcha_with_ai(page, captured)

        self.assertEqual(result, "CAPTURED_WUST")


# ------------------------------------------------------------------ #
# Endpoint fallback
# ------------------------------------------------------------------ #

class TestEndpointFallback(unittest.TestCase):
    """Test the primary → Azure endpoint fallback in _request."""

    @patch("web_crawler.ai.github_models._OPENAI_AVAILABLE", True)
    def _make_client(self):
        with patch("web_crawler.ai.github_models.OpenAI"):
            return GitHubModelsClient(token="ghp_test123")

    def test_strips_openai_prefix_for_azure(self):
        """When falling back to Azure, 'openai/' prefix is stripped."""
        client = self._make_client()
        client._model = "openai/gpt-4o"

        # Primary client raises
        client._client.chat.completions.create.side_effect = Exception("primary fail")

        # Mock the fallback OpenAI constructor
        mock_fallback_client = MagicMock()
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "test response"
        mock_fallback_client.chat.completions.create.return_value = mock_response

        with patch("web_crawler.ai.github_models.OpenAI", return_value=mock_fallback_client):
            result = client._request([{"role": "user", "content": "hello"}])

        # Verify the Azure call used model without openai/ prefix
        call_kwargs = mock_fallback_client.chat.completions.create.call_args
        model_used = call_kwargs.kwargs.get("model") or call_kwargs[1].get("model", "")
        self.assertEqual(model_used, "gpt-4o")
        self.assertEqual(result, "test response")

    def test_no_fallback_for_custom_endpoint(self):
        """Custom endpoints don't fall back to Azure."""
        with patch("web_crawler.ai.github_models._OPENAI_AVAILABLE", True):
            with patch("web_crawler.ai.github_models.OpenAI"):
                client = GitHubModelsClient(
                    token="ghp_test123",
                    endpoint="https://custom.example.com",
                )

        client._client.chat.completions.create.side_effect = Exception("fail")

        with self.assertRaises(Exception) as ctx:
            client._request([{"role": "user", "content": "hello"}])
        self.assertIn("fail", str(ctx.exception))


# ------------------------------------------------------------------ #
# LenovoIDAuth._obtain_wust_browser login button clicks
# ------------------------------------------------------------------ #

class TestLenovoIDBrowserLoginButtons(unittest.TestCase):
    """Test that _obtain_wust_browser clicks the 'Siguiente' buttons
    instead of pressing Enter for email and password submission.

    The Lenovo passport login SPA (glbwebauthnv6/preLogin) has two
    explicit buttons:
    - div.loginClass1 button (Next after email)
    - button.loadingBtnHide (Submit after password)

    These must be clicked; pressing Enter alone may not trigger the
    correct JS handler (especially nextHandler + reCAPTCHA token).
    """

    def _make_auth(self):
        from web_crawler.auth.lenovo_id import LenovoIDAuth
        return LenovoIDAuth(verify_ssl=False)

    def _make_mock_page(self, final_url="https://lsa.lenovo.com/Tips/lenovoIdSuccess.html?lenovoid.wust=MOCK_WUST"):
        """Create a mock Playwright page with locator support."""
        page = MagicMock()
        page.url = final_url

        # Create a mock locator that simulates finding elements
        def _make_locator_chain():
            loc = MagicMock()
            loc.first = loc
            loc.wait_for.return_value = None
            loc.click.return_value = None
            loc.type.return_value = None
            return loc

        page.locator.return_value = _make_locator_chain()
        page.wait_for_timeout.return_value = None
        page.wait_for_selector.return_value = MagicMock()
        page.wait_for_url.return_value = None
        page.keyboard = MagicMock()
        page.on.return_value = None
        page.goto.return_value = None
        page.content.return_value = ""
        return page

    @patch("web_crawler.auth.lenovo_id._PLAYWRIGHT_AVAILABLE", True)
    @patch("web_crawler.auth.lenovo_id._sync_playwright", create=True)
    def test_clicks_siguiente_button_after_email(self, mock_pw):
        """After entering email, the code should try to click the
        'Siguiente' button in div.loginClass1 instead of just pressing Enter."""
        auth = self._make_auth()

        page = self._make_mock_page()

        # Track which selectors were used with locator()
        locator_selectors = []
        def _track_locator(sel):
            locator_selectors.append(sel)
            loc = MagicMock()
            loc.first = loc
            loc.wait_for.return_value = None
            loc.click.return_value = None
            loc.type.return_value = None
            return loc

        page.locator.side_effect = _track_locator

        # Set up the Playwright context mock
        mock_browser = MagicMock()
        mock_ctx = MagicMock()
        mock_ctx.new_page.return_value = page
        mock_browser.new_context.return_value = mock_ctx
        mock_pw_instance = MagicMock()
        mock_pw_instance.firefox.launch.return_value = mock_browser
        mock_pw.return_value.__enter__ = MagicMock(return_value=mock_pw_instance)
        mock_pw.return_value.__exit__ = MagicMock(return_value=False)

        auth._obtain_wust_browser("test@example.com", "pass123", "https://passport.lenovo.com/test")

        # Verify that a button selector for "Siguiente" was used
        siguiente_selectors = [s for s in locator_selectors if 'Siguiente' in s or 'loginClass1' in s]
        self.assertTrue(
            len(siguiente_selectors) > 0,
            f"Expected 'Siguiente' or 'loginClass1' button selector, got: {locator_selectors}"
        )

    @patch("web_crawler.auth.lenovo_id._PLAYWRIGHT_AVAILABLE", True)
    @patch("web_crawler.auth.lenovo_id._sync_playwright", create=True)
    def test_clicks_submit_button_after_password(self, mock_pw):
        """After entering password, the code should try to click the submit
        button (button.loadingBtnHide) instead of just pressing Enter."""
        auth = self._make_auth()

        page = self._make_mock_page()

        locator_selectors = []
        def _track_locator(sel):
            locator_selectors.append(sel)
            loc = MagicMock()
            loc.first = loc
            loc.wait_for.return_value = None
            loc.click.return_value = None
            loc.type.return_value = None
            return loc

        page.locator.side_effect = _track_locator

        mock_browser = MagicMock()
        mock_ctx = MagicMock()
        mock_ctx.new_page.return_value = page
        mock_browser.new_context.return_value = mock_ctx
        mock_pw_instance = MagicMock()
        mock_pw_instance.firefox.launch.return_value = mock_browser
        mock_pw.return_value.__enter__ = MagicMock(return_value=mock_pw_instance)
        mock_pw.return_value.__exit__ = MagicMock(return_value=False)

        auth._obtain_wust_browser("test@example.com", "pass123", "https://passport.lenovo.com/test")

        # Verify that the submit button selector was used
        submit_selectors = [s for s in locator_selectors if 'loadingBtnHide' in s or 'loginClass2' in s]
        self.assertTrue(
            len(submit_selectors) > 0,
            f"Expected 'loadingBtnHide' or 'loginClass2' submit selector, got: {locator_selectors}"
        )

    @patch("web_crawler.auth.lenovo_id._PLAYWRIGHT_AVAILABLE", True)
    @patch("web_crawler.auth.lenovo_id._sync_playwright", create=True)
    def test_password_field_selectors_include_loginClass2(self, mock_pw):
        """Password field selectors should include div.loginClass2 input[type='password']
        as a fallback when #emailOrPhonePswInput is not found."""
        auth = self._make_auth()

        page = self._make_mock_page()

        locator_selectors = []
        def _track_locator(sel):
            locator_selectors.append(sel)
            loc = MagicMock()
            loc.first = loc
            # Email field works
            if sel == '#emailOrPhoneInput':
                loc.wait_for.return_value = None
                loc.click.return_value = None
                loc.type.return_value = None
                return loc
            # Make #emailOrPhonePswInput fail so the loginClass2 selector is tried
            if sel == '#emailOrPhonePswInput':
                loc.wait_for.side_effect = Exception("not found")
                return loc
            # All other selectors succeed
            loc.wait_for.return_value = None
            loc.click.return_value = None
            loc.type.return_value = None
            return loc

        page.locator.side_effect = _track_locator

        mock_browser = MagicMock()
        mock_ctx = MagicMock()
        mock_ctx.new_page.return_value = page
        mock_browser.new_context.return_value = mock_ctx
        mock_pw_instance = MagicMock()
        mock_pw_instance.firefox.launch.return_value = mock_browser
        mock_pw.return_value.__enter__ = MagicMock(return_value=mock_pw_instance)
        mock_pw.return_value.__exit__ = MagicMock(return_value=False)

        auth._obtain_wust_browser("test@example.com", "pass123", "https://passport.lenovo.com/test")

        # Verify password field selector includes loginClass2 as fallback
        pwd_selectors = [s for s in locator_selectors if "loginClass2" in s and "password" in s]
        self.assertTrue(
            len(pwd_selectors) > 0,
            f"Expected loginClass2 password selector, got: {locator_selectors}"
        )

    @patch("web_crawler.auth.lenovo_id._PLAYWRIGHT_AVAILABLE", True)
    @patch("web_crawler.auth.lenovo_id._sync_playwright", create=True)
    def test_falls_back_to_enter_when_button_not_found(self, mock_pw):
        """If the Siguiente button is not found, fallback to pressing Enter."""
        auth = self._make_auth()

        page = self._make_mock_page()

        def _failing_locator(sel):
            loc = MagicMock()
            loc.first = loc
            # Email field locators succeed
            if sel == '#emailOrPhoneInput':
                loc.wait_for.return_value = None
                loc.click.return_value = None
                loc.type.return_value = None
                return loc
            # Password field locators succeed
            if sel == '#emailOrPhonePswInput':
                loc.wait_for.return_value = None
                loc.click.return_value = None
                loc.type.return_value = None
                return loc
            # Button locators fail
            loc.wait_for.side_effect = Exception("not found")
            return loc

        page.locator.side_effect = _failing_locator

        mock_browser = MagicMock()
        mock_ctx = MagicMock()
        mock_ctx.new_page.return_value = page
        mock_browser.new_context.return_value = mock_ctx
        mock_pw_instance = MagicMock()
        mock_pw_instance.firefox.launch.return_value = mock_browser
        mock_pw.return_value.__enter__ = MagicMock(return_value=mock_pw_instance)
        mock_pw.return_value.__exit__ = MagicMock(return_value=False)

        auth._obtain_wust_browser("test@example.com", "pass123", "https://passport.lenovo.com/test")

        # When buttons are not found, Enter should be pressed as fallback
        enter_calls = [c for c in page.keyboard.press.call_args_list if c[0][0] == "Enter"]
        self.assertTrue(
            len(enter_calls) >= 2,
            f"Expected at least 2 Enter fallbacks, got {len(enter_calls)}: {page.keyboard.press.call_args_list}"
        )


if __name__ == "__main__":
    unittest.main()
