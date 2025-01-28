from setuptools import find_packages, setup

try:
    long_description = open("README.md", "r", encoding="utf-8").read()
except FileNotFoundError:
    long_description = (
        "A Python library for secure AES and RSA encryption with key management."
    )

setup(
    name="cipher_craft",
    version="1.0.0",
    description="A Python library for secure AES and RSA encryption with key management.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Onslaught2342",
    author_email="onslaught2342@outlook.com",
    url="https://github.com/onslaught-2342/CipherCraft",
    packages=find_packages(),
    install_requires=[
        "cryptography>=3.3.2",
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: Creative Commons Attribution-NonCommercial 4.0 International License",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
        "Intended Audience :: Developers",
        "Development Status :: 4 - Beta",
    ],
    python_requires=">=3.7",
    license="CC BY-NC 4.0",
    include_package_data=True,
)
