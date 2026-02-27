"""Package setup for web_crawler."""

from setuptools import setup, find_packages

setup(
    name="web-crawler",
    version="2.0.0",
    description="Generic web crawler that downloads all reachable pages and assets from a website",
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.10",
    install_requires=[
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=5.0.0",
        "urllib3>=2.0.0",
    ],
    extras_require={
        "ui": [
            "tqdm>=4.66.0",
            "colorlog>=6.8.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "web-crawler=web_crawler.cli:main",
        ],
    },
)
