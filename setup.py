from pathlib import Path

from setuptools import find_packages, setup


BASE_DIR = Path(__file__).parent
README = BASE_DIR / "README.md"

setup(
    name="cryptoden",
    version="1.0.0",
    description="CTF加解密工具箱 - CTF Cryptography Tool",
    license="MIT",
    long_description=README.read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    author="Cryptoden Team",
    packages=find_packages(exclude=("tests", "tests.*")),
    py_modules=[
        "cli",
        "de_all",
        "de_recursion",
        "main",
        "match_input",
    ],
    include_package_data=True,
    package_data={
        "agent": ["agent_config.json"],
        "config": ["ai_config.json"],
    },
    install_requires=[
        "PyQt5>=5.15.0",
        "pycryptodome>=3.15.0",
        "requests>=2.28.0",
        "cryptography>=42.0.0",
        "numpy>=1.26.0",
        "markdown>=3.5.0",
        "pycryptodomex>=3.20.0",
    ],
    entry_points={
        "console_scripts": [
            "cryptoden=cli:main",
            "cryptoden-gui=main:main",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Education",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
        "Topic :: Utilities",
    ],
)
