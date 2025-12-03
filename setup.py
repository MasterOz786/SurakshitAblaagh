from setuptools import setup, find_packages

setup(
    name="securelink",
    version="0.1.0",
    description="Secure tunnel library for multiple services over a single port using QUIC",
    author="",
    packages=find_packages(),
    install_requires=[
        "aioquic>=0.9.20",
        "cryptography>=41.0.0",
        "pynacl>=1.5.0",
        "base91>=1.0.1",
        "structlog>=23.0.0",
    ],
    python_requires=">=3.8",
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
        ],
    },
)

