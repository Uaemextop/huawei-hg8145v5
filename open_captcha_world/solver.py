"""
AI-powered CAPTCHA solver using the GitHub Models vision API.

Uses :class:`~web_crawler.ai.github_models.GitHubModelsClient` to analyse
puzzle images and return answers.  Each CAPTCHA type from OpenCaptchaWorld
gets a specialised prompt that describes the puzzle and asks the model to
return a structured JSON answer.
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any, Optional

# Re-use the existing GitHub Models client from the web_crawler package.
from web_crawler.ai.github_models import GitHubModelsClient

# ---------------------------------------------------------------------------
# Per-type solver prompts
# ---------------------------------------------------------------------------
# Each prompt instructs the vision model to examine the puzzle image and
# return a JSON answer in the format expected by the OpenCaptchaWorld
# ground-truth schema.

_TYPE_PROMPTS: dict[str, str] = {
    "Dice_Count": (
        "This image shows several dice. Count ALL the visible numbers "
        "on every die and compute the total sum. "
        'Return ONLY a JSON object: {"sum": <integer>}'
    ),
    "Geometry_Click": (
        "This image shows geometric shapes with letters. "
        "Follow the instruction in the image (e.g. 'Click the Letter "
        "on the left of the Parallelogram'). "
        "Identify the correct letter and its approximate bounding box "
        "as [[x1,y1],[x2,y2]] in pixel coordinates. "
        'Return ONLY a JSON object: {"type": "<letter>", "area": [[x1,y1],[x2,y2]]}'
    ),
    "Rotation_Match": (
        "This image shows a reference direction and an object. "
        "Determine the angle in degrees (0, 90, 180, 270) the object "
        "must be rotated so it faces the reference direction. "
        'Return ONLY a JSON object: {"answer": <degrees>}'
    ),
    "Slide_Puzzle": (
        "This image shows a sliding puzzle with a component piece. "
        "Determine the [x, y] pixel position where the component "
        "should be placed to complete the puzzle. "
        'Return ONLY a JSON object: {"answer": [x, y]}'
    ),
    "Unusual_Detection": (
        "This image shows a grid of animals. Some have the wrong head "
        "(mismatched head/body). Identify the 0-based grid indices of "
        "the animals with wrong heads. Grid is read left-to-right, "
        "top-to-bottom. "
        'Return ONLY a JSON object: {"answer": [index1, index2, ...]}'
    ),
    "Image_Recognition": (
        "This image shows a grid of pictures. The instruction asks you "
        "to find images containing a specific object. "
        "Return the 1-based indices of ALL matching images. "
        'Return ONLY a JSON object: {"correct_selections": [1, 3, 5, ...]}'
    ),
    "Bingo": (
        "This image shows a grid of emojis/images. You need to swap "
        "two cells so that identical images form a line (row, column, "
        "or diagonal). Identify the two 0-based cell indices to swap. "
        'Return ONLY a JSON object: {"answer": [[row1,col1],[row2,col2]]}'
    ),
    "Image_Matching": (
        "This image shows a reference image on the left and several "
        "option images. Select the option that matches the animal in "
        "the reference. Return the 0-based index of the correct option. "
        'Return ONLY a JSON object: {"correct_option_index": <int>}'
    ),
    "Object_Match": (
        "This image shows a reference with some objects and several "
        "options. Pick the option whose count matches the reference. "
        "Return the 0-based index. "
        'Return ONLY a JSON object: {"correct_option_index": <int>}'
    ),
    "Patch_Select": (
        "This image is divided into a grid of patches. Select all "
        "patches that contain the target object mentioned in the "
        "instruction. Return 0-based patch indices (left-to-right, "
        "top-to-bottom). "
        'Return ONLY a JSON object: {"correct_patches": [0, 1, 5, ...]}'
    ),
    "Select_Animal": (
        "This image shows a grid of animal images. Pick the cell that "
        "contains the target animal. Return 0-based indices. "
        'Return ONLY a JSON object: {"correct_patches": [index]}'
    ),
    "Dart_Count": (
        "This image shows a reference number and several dartboard "
        "images. Find the dartboard where the darts add up to the "
        "reference number. Return the 0-based index. "
        'Return ONLY a JSON object: {"correct_option_index": <int>}'
    ),
    "Path_Finder": (
        "This image shows a path puzzle. Determine which option image "
        "has the object placed at the position indicated by the cross. "
        "Return the 0-based index. "
        'Return ONLY a JSON object: {"correct_option": <int>}'
    ),
    "Coordinates": (
        "This image shows a reference image indicating a target "
        "position and several option images. Find the option where the "
        "character is at the indicated position. Return the 0-based index. "
        'Return ONLY a JSON object: {"correct_option_index": <int>}'
    ),
    "Connect_icon": (
        "This image shows a reference connection pattern and several "
        "option images. Find the option that matches the connection "
        "shown in the reference. Return the 0-based index. "
        'Return ONLY a JSON object: {"correct_option": <int>}'
    ),
    "Click_Order": (
        "This image shows icons that need to be clicked in a specific "
        "order shown in a reference. Return the [x,y] pixel coordinates "
        "for each click point in the correct order. "
        'Return ONLY a JSON object: {"answer": [[x1,y1],[x2,y2],...]}'
    ),
    "Place_Dot": (
        "This image shows a path and you need to place a dot at the "
        "end of the path. Return the [x,y] pixel coordinates. "
        'Return ONLY a JSON object: {"target_position": [x, y]}'
    ),
    "Pick_Area": (
        "This image shows areas outlined by dotted lines. Click on "
        "the center of the largest outlined area. Return the [x,y] "
        "pixel coordinates of that center. "
        'Return ONLY a JSON object: {"answer": [x, y]}'
    ),
    "Misleading_Click": (
        "This image has a misleading element that says 'Don't click me'. "
        "Identify a safe area to click that avoids the red/warning area. "
        'Return ONLY a JSON object: {"answer": [x, y]}'
    ),
    "Hold_Button": (
        'This is a hold-button CAPTCHA. Return: {"answer": "completed"}'
    ),
}

_DEFAULT_PROMPT = (
    "Analyse this CAPTCHA puzzle image carefully. "
    "Describe what type of puzzle it is and provide the solution. "
    "Return your answer as a JSON object with an 'answer' key."
)


class CaptchaSolver:
    """Solve OpenCaptchaWorld puzzles using GitHub Models vision API.

    Parameters
    ----------
    token : str | None
        GitHub PAT.  Falls back to ``GITHUB_TOKEN`` or ``AI_TOKEN`` env var.
    model : str
        GitHub Models vision model (default ``openai/gpt-4o``).
    """

    def __init__(
        self,
        token: Optional[str] = None,
        model: str = "openai/gpt-4o",
    ) -> None:
        tok = (
            token
            or os.environ.get("GITHUB_TOKEN", "")
            or os.environ.get("AI_TOKEN", "")
        )
        self._client = GitHubModelsClient(token=tok, model=model)

    def solve(
        self,
        captcha_type: str,
        image_base64: str,
        prompt: str = "",
        *,
        mime_type: str = "image/png",
    ) -> dict[str, Any]:
        """Solve a CAPTCHA puzzle.

        Parameters
        ----------
        captcha_type : str
            One of the 20 OpenCaptchaWorld types (e.g. ``"Dice_Count"``).
        image_base64 : str
            Base64-encoded puzzle image.
        prompt : str
            Optional puzzle-specific prompt override (from ground_truth).
        mime_type : str
            Image MIME type.

        Returns
        -------
        dict
            ``{"success": True, "answer": ..., "raw": "..."}`` on success,
            ``{"success": False, "error": "..."}`` on failure.
        """
        type_prompt = _TYPE_PROMPTS.get(captcha_type, _DEFAULT_PROMPT)
        if prompt:
            full_prompt = f"Puzzle instruction: {prompt}\n\n{type_prompt}"
        else:
            full_prompt = type_prompt

        try:
            raw = self._client.chat(
                prompt=full_prompt,
                image_base64=image_base64,
                mime_type=mime_type,
                system_prompt=(
                    "You are an expert CAPTCHA puzzle solver. "
                    "Analyse the image carefully and return ONLY "
                    "valid JSON — no markdown, no explanation."
                ),
            )
        except Exception as exc:
            return {"success": False, "error": str(exc)}

        if not raw:
            return {"success": False, "error": "Empty AI response"}

        # Parse the JSON from the AI response
        answer = _parse_json_answer(raw)
        return {
            "success": True,
            "answer": answer,
            "raw": raw,
        }

    def solve_from_file(
        self,
        captcha_type: str,
        image_path: str,
        prompt: str = "",
    ) -> dict[str, Any]:
        """Convenience: load an image file and solve it."""
        with open(image_path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode("ascii")
        import mimetypes as _mt
        mime = _mt.guess_type(image_path)[0] or "image/png"
        return self.solve(captcha_type, b64, prompt, mime_type=mime)


def _parse_json_answer(raw: str) -> Any:
    """Extract a JSON object from the AI response text.

    The model sometimes wraps JSON in markdown fences — strip those.
    """
    text = raw.strip()
    # Strip markdown code fences
    if text.startswith("```"):
        lines = text.split("\n")
        # Remove first and last fence lines
        lines = [l for l in lines if not l.strip().startswith("```")]
        text = "\n".join(lines).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try to find a JSON object in the text
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                pass
        # Try to find a JSON array
        start = text.find("[")
        end = text.rfind("]")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                pass
        # Return raw text as fallback
        return text
