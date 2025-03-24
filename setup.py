from setuptools import setup, find_packages

setup(
    name="StegaCrypt",
    version="1.0.0",
    author="Team Cyfer Trace",
    description="A CLI tool for image steganography with encryption and decryption",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/your-repo/StegaCrypt",
    license="MIT",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    packages=find_packages(),
    install_requires=[
        "click",
        "cryptography",
    ],
    entry_points={
        "console_scripts": [
            "stegacrypt=steganography.cli:main",
        ],
    },
    python_requires=">=3.7",
)
