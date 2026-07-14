"""Setup script for RepoSentinel."""

from setuptools import setup, find_packages

setup(
    name="reposentinel",
    version="1.0.0",
    description="GitHub Repository Malicious Code Scanner — Protect yourself from malicious scripts",
    long_description=open("README.md", encoding="utf-8").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="RepoSentinel Team",
    license="MIT",
    packages=find_packages(),
    include_package_data=True,
    package_data={
        "reposentinel": ["database/patterns/*.yaml"],
    },
    install_requires=[
        "click>=8.1.0",
        "rich>=13.0.0",
        "gitpython>=3.1.0",
        "pyyaml>=6.0.0",
        "requests>=2.31.0",
    ],
    entry_points={
        "console_scripts": [
            "catpaw=reposentinel.cli:main",
        ],
    },
    python_requires=">=3.9",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
)
