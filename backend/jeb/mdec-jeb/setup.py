#!/usr/bin/env python3
from setuptools import setup


__version__ = '0.0.1'


setup(name='mdec-jeb',
	  version=__version__,
	  description='mdec-jeb',
	  packages=['mdecjeb'],
	  install_requires=['mdec-base'],
	  python_requires='>=3.6'
	  )
