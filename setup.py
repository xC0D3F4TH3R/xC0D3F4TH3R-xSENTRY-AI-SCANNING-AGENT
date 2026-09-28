from setuptools import setup, find_packages

setup(
    name="sentryscan",
    version="0.1.0",
    description="NLP-driven Nmap wrapper: intent-based port discovery, service enumeration, and AI summaries.",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=["anthropic>=0.34.0"],
    entry_points={
        "console_scripts": [
            "sentryscan=sentryscan.cli:main",
        ],
    },
)
