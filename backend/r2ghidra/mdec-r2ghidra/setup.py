#!/usr/bin/env python3
from setuptools import setup

__version__ = '0.0.1'


setup(name='mdec-r2ghidra',
      version=__version__,
      description='mdec-r2ghidra',
      packages=['mdecr2ghidra'],
      install_requires=['mdec-base', 'r2pipe'],
      python_requires='>=3.8'
      )
