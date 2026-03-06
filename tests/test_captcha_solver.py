"""Tests for open_captcha_world.solver module."""

import json
import os
import unittest
from unittest.mock import MagicMock, patch

from open_captcha_world.solver import (
    CaptchaSolver,
    _parse_json_answer,
    _TYPE_PROMPTS,
    _DEFAULT_PROMPT,
)


class TestParseJsonAnswer(unittest.TestCase):
    """Tests for _parse_json_answer helper."""

    def test_plain_json(self):
        result = _parse_json_answer('{"sum": 85}')
        self.assertEqual(result, {"sum": 85})

    def test_json_with_markdown_fences(self):
        raw = "```json\n{\"answer\": 42}\n```"
        result = _parse_json_answer(raw)
        self.assertEqual(result, {"answer": 42})

    def test_json_embedded_in_text(self):
        raw = 'The answer is {"answer": [1, 2, 3]} here.'
        result = _parse_json_answer(raw)
        self.assertEqual(result, {"answer": [1, 2, 3]})

    def test_json_array(self):
        raw = "The patches are [0, 1, 5, 6]"
        result = _parse_json_answer(raw)
        self.assertEqual(result, [0, 1, 5, 6])

    def test_fallback_to_raw_text(self):
        raw = "I don't know"
        result = _parse_json_answer(raw)
        self.assertEqual(result, "I don't know")

    def test_empty_string(self):
        result = _parse_json_answer("")
        self.assertEqual(result, "")

    def test_nested_json(self):
        raw = '{"type": "Letter A", "area": [[50, 35], [90, 80]]}'
        result = _parse_json_answer(raw)
        self.assertEqual(result, {
            "type": "Letter A",
            "area": [[50, 35], [90, 80]],
        })


class TestTypePrompts(unittest.TestCase):
    """Ensure all 20 puzzle types have dedicated prompts."""

    KNOWN_TYPES = [
        "Dice_Count", "Geometry_Click", "Rotation_Match", "Slide_Puzzle",
        "Unusual_Detection", "Image_Recognition", "Bingo", "Image_Matching",
        "Object_Match", "Patch_Select", "Select_Animal", "Dart_Count",
        "Path_Finder", "Coordinates", "Connect_icon", "Click_Order",
        "Place_Dot", "Pick_Area", "Misleading_Click", "Hold_Button",
    ]

    def test_all_types_present(self):
        for t in self.KNOWN_TYPES:
            self.assertIn(t, _TYPE_PROMPTS, f"Missing prompt for {t}")

    def test_prompts_non_empty(self):
        for t, prompt in _TYPE_PROMPTS.items():
            self.assertTrue(prompt.strip(), f"Empty prompt for {t}")

    def test_default_prompt_exists(self):
        self.assertTrue(_DEFAULT_PROMPT.strip())


class TestCaptchaSolver(unittest.TestCase):
    """Tests for CaptchaSolver class."""

    @patch.dict(os.environ, {"GITHUB_TOKEN": ""}, clear=False)
    def test_raises_without_token(self):
        """Solver raises ValueError when no token is available."""
        with self.assertRaises((ValueError, Exception)):
            CaptchaSolver(token="")

    @patch("open_captcha_world.solver.GitHubModelsClient")
    def test_solve_returns_success(self, MockClient):
        """Solver returns structured result on success."""
        mock_instance = MagicMock()
        mock_instance.chat.return_value = '{"sum": 42}'
        MockClient.return_value = mock_instance

        solver = CaptchaSolver.__new__(CaptchaSolver)
        solver._client = mock_instance

        result = solver.solve("Dice_Count", "base64data", "Sum up the dice")
        self.assertTrue(result["success"])
        self.assertEqual(result["answer"], {"sum": 42})

    @patch("open_captcha_world.solver.GitHubModelsClient")
    def test_solve_returns_error_on_exception(self, MockClient):
        """Solver returns error dict when AI call fails."""
        mock_instance = MagicMock()
        mock_instance.chat.side_effect = RuntimeError("API error")
        MockClient.return_value = mock_instance

        solver = CaptchaSolver.__new__(CaptchaSolver)
        solver._client = mock_instance

        result = solver.solve("Dice_Count", "base64data")
        self.assertFalse(result["success"])
        self.assertIn("API error", result["error"])

    @patch("open_captcha_world.solver.GitHubModelsClient")
    def test_solve_returns_error_on_empty(self, MockClient):
        """Solver returns error when AI returns empty string."""
        mock_instance = MagicMock()
        mock_instance.chat.return_value = ""
        MockClient.return_value = mock_instance

        solver = CaptchaSolver.__new__(CaptchaSolver)
        solver._client = mock_instance

        result = solver.solve("Dice_Count", "base64data")
        self.assertFalse(result["success"])

    @patch("open_captcha_world.solver.GitHubModelsClient")
    def test_solve_with_prompt_override(self, MockClient):
        """Prompt override is passed to the AI model."""
        mock_instance = MagicMock()
        mock_instance.chat.return_value = '{"answer": 90}'
        MockClient.return_value = mock_instance

        solver = CaptchaSolver.__new__(CaptchaSolver)
        solver._client = mock_instance

        result = solver.solve(
            "Rotation_Match", "base64data",
            prompt="Rotate the cat to face right"
        )
        self.assertTrue(result["success"])
        # Verify the prompt was included
        call_args = mock_instance.chat.call_args
        self.assertIn("Rotate the cat to face right", call_args.kwargs["prompt"])

    @patch("open_captcha_world.solver.GitHubModelsClient")
    def test_solve_unknown_type_uses_default(self, MockClient):
        """Unknown puzzle types get the default generic prompt."""
        mock_instance = MagicMock()
        mock_instance.chat.return_value = '{"answer": "test"}'
        MockClient.return_value = mock_instance

        solver = CaptchaSolver.__new__(CaptchaSolver)
        solver._client = mock_instance

        result = solver.solve("UnknownType", "base64data")
        self.assertTrue(result["success"])
        call_args = mock_instance.chat.call_args
        self.assertIn("Analyse this CAPTCHA", call_args.kwargs["prompt"])


if __name__ == "__main__":
    unittest.main()
