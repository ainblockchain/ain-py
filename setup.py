from setuptools import setup, find_packages
from pathlib import Path

this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

requirements = [
    "typing-extensions==4.7.1",
    "pycryptodome==3.18.0",
    "coincurve==18.0.0",
    "aiohttp[speedups]==3.8.5",
    "jsonrpcclient==4.0.3",
    "mnemonic==0.20",
    "bip32==3.4",
]

test_requirements = []

setup(
    author="AIN Dev Team",
    author_email="dev@ainetwork.ai",
    python_requires=">=3.7",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
        "Natural Language :: English",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    description="AI Network Client Library for Python3",
    install_requires=requirements,
    license="MPL license",
    long_description=long_description,
    long_description_content_type='text/markdown',
    include_package_data=True,
    keywords=["ain", "ainetwork", "ainblockchain", "API"],
    name="ain-py",
    packages=find_packages(include=["ain", "ain.*"]),
    test_suite="tests",
    tests_require=test_requirements,
    url="https://github.com/ainblockchain/ain-py",
    version="1.0.3",
    zip_safe=False,
)
