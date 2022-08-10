from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand

VERSION = "1.0.5"
DOC_DIR = "FAQ.md"

setup(
    name="PVMScanner",
    version=VERSION,
    description="A web application vulnerability scanner",
    long_description="""\To be Added""",
    url="Add Github",
    author="Yuriy Ivanov",
    author_email="yuriy.ivanov@city.ac.uk",
    platforms=["Any"],
    packages=find_packages(),
    include_package_data=True,
    scripts=[
      
    ],
    classifiers=[
        "Topic :: Software Development :: Testing"
    ],
    install_requires=[
        'Click'
    ],
    extras_require={
       
    },
    entry_points={
      
    },
    tests_require=["pytest>=6.2.2", "respx==0.19.2", "pytest-cov>=2.11.1", "pytest-asyncio==0.14.0"],
    setup_requires=["pytest-runner"],
)