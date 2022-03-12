#!/usr/bin/env python3
from setuptools import setup


__version__ = '0.0.1'


setup(name='mdec-ghidra',
	  version=__version__,
	  description='mdec-ghidra',
	  packages=['mdecghidra'],
	  install_requires=['mdec-base'],
	  python_requires='>=3.6'
	  )
