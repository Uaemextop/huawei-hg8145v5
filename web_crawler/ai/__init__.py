"""
AI-powered utilities for the web crawler.

Adapted from `Auto_CAPTCHA_with_LLM <https://github.com/erichung9060/Auto_CAPTCHA_with_LLM>`_
to use the **GitHub Models** inference API (``models.inference.ai.azure.com``)
instead of Gemini / Google Cloud Vision, and **Playwright** for browser
automation instead of Chrome extension APIs.

Provides:
* GitHub Models API client with vision (image) support
* AI-powered CAPTCHA solver using Playwright browser control + vision model
* Text extraction from images
"""
