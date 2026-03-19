"""Package setup for web_crawler + crawl4ai combined project."""

from setuptools import setup, find_packages

setup(
    name="web-crawler",
    version="3.0.0",
    description="Combined web crawler: crawl4ai async engine + Huawei HG8145V5 specialised crawler",
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.10",
    install_requires=[
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=5.0.0",
        "urllib3>=2.0.0",
        "pydantic>=2.10",
        "aiofiles>=24.1.0",
        "aiohttp>=3.11.11",
        "aiosqlite>=0.20",
        "anyio>=4.0.0",
        "python-dotenv>=1.0",
        "xxhash>=3.4",
        "rank-bm25>=0.2",
        "colorama>=0.4",
        "snowballstemmer>=2.2",
        "psutil>=6.1.1",
        "PyYAML>=6.0",
        "nltk>=3.9.1",
        "rich>=13.9.4",
        "cssselect>=1.2.0",
        "chardet>=5.2.0",
        "httpx[http2]>=0.27.2",
        "fake-useragent>=2.2.0",
    ],
    extras_require={
        "ui": [
            "tqdm>=4.66.0",
            "colorlog>=6.8.0",
        ],
        "llm": [
            "litellm>=1.53.1",
        ],
        "browser": [
            "playwright>=1.49.0",
            "patchright>=1.49.0",
            "tf-playwright-stealth>=1.1.0",
        ],
        "images": [
            "numpy>=1.26.0,<3",
            "pillow>=10.4",
        ],
    },
    entry_points={
        "console_scripts": [
            "web-crawler=web_crawler.cli:main",
        ],
    },
)
