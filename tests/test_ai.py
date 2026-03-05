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


if __name__ == "__main__":
    unittest.main()
