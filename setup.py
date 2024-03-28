#!/usr/bin/env python3

import setuptools

from cis_audit import __version__

setuptools.setup(
    name="cis-benchmarks-audit",
    version=__version__,
    author="Andy Dustin",
    author_email="andy.dustin@gmail.com",
    description="Check systems conformance to CIS Hardening benchmarks",
    packages=setuptools.find_packages(),
    py_modules=['cis_audit'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
    ],
    python_requires='~=3.6',
)
