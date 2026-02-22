"""Package setup for huawei_crawler."""

from setuptools import setup, find_packages

setup(
    name="huawei-crawler",
    version="1.0.0",
    description="Web crawler for the Huawei HG8145V5 router admin interface",
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
            "huawei-crawler=huawei_crawler.cli:main",
        ],
    },
)
