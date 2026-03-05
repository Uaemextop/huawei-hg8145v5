"""
GitHub Models API client with vision (image) support.

Adapted from `Auto_CAPTCHA_with_LLM <https://github.com/erichung9060/Auto_CAPTCHA_with_LLM>`_
(background.js ``recognize_by_Gemini`` / ``recognize_by_CloudVision``) to use
the **GitHub Models** inference endpoint via the **OpenAI Python SDK** instead
of Gemini or Cloud Vision.

The client replicates the same CAPTCHA-type prompts (``numbersOnly``,
``lettersOnly``, ``auto``) and alphanumeric-only post-processing from the
original extension, but targets the GitHub Models inference API::

    from openai import OpenAI

    client = OpenAI(
        base_url="https://models.github.ai/inference",
        api_key=os.environ["GITHUB_TOKEN"],
    )

Authentication is via a GitHub personal access token (PAT) passed through
the ``GITHUB_TOKEN`` environment variable or explicitly at construction time.
"""

import base64
import mimetypes
import os
import re
from pathlib import Path
from typing import Any, Optional

import requests as _requests_lib  # only used for image URL fetching

from web_crawler.utils.log import log

try:
    from openai import OpenAI
    _OPENAI_AVAILABLE = True
except ImportError:
    _OPENAI_AVAILABLE = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_GITHUB_MODELS_ENDPOINT = "https://models.github.ai/inference"
_GITHUB_MODELS_ENDPOINT_AZURE = "https://models.inference.ai.azure.com"
_DEFAULT_MODEL = "openai/gpt-4o"
_DEFAULT_MAX_TOKENS = 1024
_DEFAULT_TEMPERATURE = 0.2
_REQUEST_TIMEOUT = 60

# CAPTCHA type constants — mirror the Chrome extension's radio values.
CAPTCHA_TYPE_NUMBERS = "numbersOnly"
CAPTCHA_TYPE_LETTERS = "lettersOnly"
CAPTCHA_TYPE_AUTO = "auto"

# Prompts adapted from background.js ``recognize_by_Gemini``.
_CAPTCHA_PROMPTS: dict[str, str] = {
    CAPTCHA_TYPE_NUMBERS: (
        "Please analyze this CAPTCHA image. The image only contains "
        "numbers/digits with some noise/distortion. Return only the "
        "CAPTCHA numbers without any additional text or explanation."
    ),
    CAPTCHA_TYPE_LETTERS: (
        "Please analyze this CAPTCHA image. The image only contains "
        "letters/alphabetic characters with some noise/distortion. "
        "Return only the CAPTCHA letters without any additional text "
        "or explanation."
    ),
    CAPTCHA_TYPE_AUTO: (
        "Please analyze this CAPTCHA image. The image contains digits "
        "or numbers or words with some noise/distortion. Return only "
        "the CAPTCHA numbers or digits or words without any additional "
        "text or explanation."
    ),
}

# Regex used to strip non-alphanumeric noise from the AI response,
# mirroring ``verificationCode.match(/[a-zA-Z0-9]+/g).join('')`` in
# the original extension.
_ALNUM_RE = re.compile(r"[a-zA-Z0-9]+")


def _clean_verification_code(raw: str) -> str:
    """Strip everything except letters and digits (same logic as the
    original Auto_CAPTCHA_with_LLM extension)."""
    parts = _ALNUM_RE.findall(raw)
    return "".join(parts)


class GitHubModelsClient:
    """Client for the GitHub Models inference API with vision support.

    Uses the **OpenAI Python SDK** pointed at the GitHub Models endpoint,
    exactly as shown in the official GitHub Models documentation::

        from openai import OpenAI
        client = OpenAI(
            base_url="https://models.github.ai/inference",
            api_key=os.environ["GITHUB_TOKEN"],
        )

    Mirrors the recognition flow from ``Auto_CAPTCHA_with_LLM`` but
    calls GitHub Models instead of Gemini / Cloud Vision.

    Parameters
    ----------
    token : str | None
        GitHub PAT.  Falls back to ``GITHUB_TOKEN`` env var.
    model : str
        Model identifier (default ``openai/gpt-4o``).  Any model
        available on GitHub Models that supports vision can be used
        (e.g. ``openai/gpt-4o-mini``, ``openai/gpt-4o``).
    max_tokens : int
        Maximum tokens in the completion response.
    temperature : float
        Sampling temperature (0 = deterministic).
    endpoint : str | None
        Override the base URL.  Defaults to
        ``https://models.github.ai/inference``.  Falls back to
        ``https://models.inference.ai.azure.com`` on connection error.
    """

    def __init__(
        self,
        token: Optional[str] = None,
        model: str = _DEFAULT_MODEL,
        max_tokens: int = _DEFAULT_MAX_TOKENS,
        temperature: float = _DEFAULT_TEMPERATURE,
        endpoint: Optional[str] = None,
    ) -> None:
        if not _OPENAI_AVAILABLE:
            raise ImportError(
                "The openai package is required.  "
                "Install it with:  pip install openai"
            )
        self._token = token or os.environ.get("GITHUB_TOKEN", "")
        if not self._token:
            raise ValueError(
                "GitHub token is required.  Set the GITHUB_TOKEN environment "
                "variable or pass it explicitly."
            )
        self._model = model
        self._max_tokens = max_tokens
        self._temperature = temperature
        self._endpoint = endpoint or _GITHUB_MODELS_ENDPOINT
        self._client = OpenAI(
            base_url=self._endpoint,
            api_key=self._token,
        )

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    @property
    def model(self) -> str:
        """Return the model identifier in use."""
        return self._model

    def chat(
        self,
        prompt: str,
        *,
        image_base64: Optional[str] = None,
        image_url: Optional[str] = None,
        image_path: Optional[str] = None,
        mime_type: str = "image/png",
        system_prompt: str = "",
    ) -> str:
        """Send a chat completion request, optionally with an image.

        Exactly one of ``image_base64``, ``image_url``, or ``image_path``
        may be provided.  If none is given the request is text-only.

        Parameters
        ----------
        prompt : str
            User-visible text prompt.
        image_base64 : str | None
            Raw base64-encoded image data.
        image_url : str | None
            Publicly reachable image URL.
        image_path : str | None
            Local filesystem path to an image file.
        mime_type : str
            MIME type used when sending ``image_base64`` (ignored for URL).
        system_prompt : str
            Optional system-level instruction prepended to the conversation.

        Returns
        -------
        str
            The assistant's text response.
        """
        content: list[dict[str, Any]] = []

        # Resolve local file to base64
        if image_path and not image_base64:
            image_base64, mime_type = self._load_image_file(image_path)

        # Build multimodal content array (image first, then text — same
        # order as the Gemini ``inline_data`` + ``text`` parts in the
        # original extension).
        if image_base64:
            content.append({
                "type": "image_url",
                "image_url": {
                    "url": f"data:{mime_type};base64,{image_base64}",
                },
            })
        elif image_url:
            content.append({
                "type": "image_url",
                "image_url": {"url": image_url},
            })

        content.append({"type": "text", "text": prompt})

        messages: list[dict[str, Any]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": content})

        return self._request(messages)

    # ------------------------------------------------------------------
    # CAPTCHA recognition — adapted from background.js
    # ------------------------------------------------------------------

    def recognize_captcha(
        self,
        image_base64: str,
        captcha_type: str = CAPTCHA_TYPE_AUTO,
        *,
        mime_type: str = "image/png",
    ) -> dict[str, Any]:
        """Recognise a CAPTCHA image and return the verification code.

        This is the Python equivalent of the extension's
        ``recognizeCaptcha → recognize_by_Gemini`` flow, adapted for
        GitHub Models via the OpenAI SDK.

        Parameters
        ----------
        image_base64 : str
            Base64-encoded CAPTCHA image (same format as the extension's
            ``getBase64Image`` output).
        captcha_type : str
            One of ``"numbersOnly"``, ``"lettersOnly"``, or ``"auto"``.
        mime_type : str
            MIME type of the image data.

        Returns
        -------
        dict
            ``{"isSuccess": True, "verificationCode": "AB12"}`` on success,
            ``{"isSuccess": False, "error": "…"}`` on failure — matching
            the original extension's response format.
        """
        prompt = _CAPTCHA_PROMPTS.get(captcha_type, _CAPTCHA_PROMPTS[CAPTCHA_TYPE_AUTO])
        try:
            raw = self.chat(
                prompt=prompt,
                image_base64=image_base64,
                mime_type=mime_type,
            )
        except Exception as exc:
            return {"isSuccess": False, "error": str(exc)}

        if not raw:
            return {"isSuccess": False, "error": "No text detected in image."}

        verification_code = _clean_verification_code(raw)
        if not verification_code:
            return {"isSuccess": False, "error": "No text detected in image."}

        return {"isSuccess": True, "verificationCode": verification_code}

    # ------------------------------------------------------------------
    # Text extraction (OCR-like)
    # ------------------------------------------------------------------

    def extract_text(
        self,
        *,
        image_base64: Optional[str] = None,
        image_url: Optional[str] = None,
        image_path: Optional[str] = None,
        mime_type: str = "image/png",
    ) -> str:
        """Extract all visible text from an image (OCR-like).

        Returns the extracted text as a plain string.
        """
        return self.chat(
            prompt=(
                "Extract ALL visible text from this image exactly as it "
                "appears.  Return only the extracted text, nothing else."
            ),
            image_base64=image_base64,
            image_url=image_url,
            image_path=image_path,
            mime_type=mime_type,
            system_prompt=(
                "You are an OCR assistant.  Your sole task is to extract "
                "text from images with perfect accuracy."
            ),
        )

    def describe_image(
        self,
        *,
        image_base64: Optional[str] = None,
        image_url: Optional[str] = None,
        image_path: Optional[str] = None,
        mime_type: str = "image/png",
    ) -> str:
        """Return a natural-language description of an image."""
        return self.chat(
            prompt="Describe this image in detail.",
            image_base64=image_base64,
            image_url=image_url,
            image_path=image_path,
            mime_type=mime_type,
        )

    def solve_captcha_image(
        self,
        *,
        image_base64: Optional[str] = None,
        image_url: Optional[str] = None,
        image_path: Optional[str] = None,
        mime_type: str = "image/png",
        captcha_type: str = CAPTCHA_TYPE_AUTO,
    ) -> str:
        """Analyse a CAPTCHA image and return **only** the solution text.

        Convenience wrapper around :meth:`recognize_captcha` that returns
        a plain string (empty on failure).
        """
        b64 = image_base64
        if image_path and not b64:
            b64, mime_type = self._load_image_file(image_path)
        if image_url and not b64:
            b64 = self._fetch_image_url(image_url)
        if not b64:
            return ""
        result = self.recognize_captcha(b64, captcha_type, mime_type=mime_type)
        return result.get("verificationCode", "") if result.get("isSuccess") else ""

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _load_image_file(path: str) -> tuple[str, str]:
        """Read a local image file and return ``(base64_data, mime_type)``."""
        p = Path(path)
        if not p.is_file():
            raise FileNotFoundError(f"Image file not found: {path}")
        data = p.read_bytes()
        b64 = base64.b64encode(data).decode("ascii")
        guessed = mimetypes.guess_type(str(p))[0] or "image/png"
        return b64, guessed

    @staticmethod
    def _fetch_image_url(url: str) -> Optional[str]:
        """Download an image from *url* and return base64 data.

        Mirrors the extension's ``fetchImageAsBase64`` helper in
        background.js.
        """
        try:
            resp = _requests_lib.get(url, timeout=_REQUEST_TIMEOUT)
            resp.raise_for_status()
            return base64.b64encode(resp.content).decode("ascii")
        except Exception as exc:
            log.debug("[AI] Failed to fetch image URL %s: %s", url, exc)
            return None

    def _request(self, messages: list[dict[str, Any]]) -> str:
        """Send a chat-completion request via the OpenAI SDK and return
        the assistant text.

        If the primary endpoint (``models.github.ai``) fails with a
        connection or 404 error, automatically falls back to the Azure
        endpoint (``models.inference.ai.azure.com``) and adapts the
        model name (strips ``openai/`` prefix if present).
        """
        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=messages,
                max_tokens=self._max_tokens,
                temperature=self._temperature,
            )
        except Exception as exc:
            # Attempt fallback to Azure endpoint if the primary failed
            if self._endpoint == _GITHUB_MODELS_ENDPOINT:
                log.info(
                    "[AI] Primary endpoint failed, trying Azure fallback: %s",
                    exc,
                )
                try:
                    fallback = OpenAI(
                        base_url=_GITHUB_MODELS_ENDPOINT_AZURE,
                        api_key=self._token,
                    )
                    # Azure endpoint uses model names without the
                    # ``openai/`` prefix (e.g. ``gpt-4o`` not
                    # ``openai/gpt-4o``).
                    azure_model = self._model
                    if azure_model.startswith("openai/"):
                        azure_model = azure_model[len("openai/"):]
                    response = fallback.chat.completions.create(
                        model=azure_model,
                        messages=messages,
                        max_tokens=self._max_tokens,
                        temperature=self._temperature,
                    )
                except Exception as exc2:
                    log.error(
                        "[AI] Azure fallback also failed: %s", exc2,
                    )
                    raise
            else:
                log.error("[AI] GitHub Models API request failed: %s", exc)
                raise

        choices = response.choices
        if not choices:
            log.warning("[AI] Empty response from GitHub Models API")
            return ""
        return (choices[0].message.content or "").strip()
