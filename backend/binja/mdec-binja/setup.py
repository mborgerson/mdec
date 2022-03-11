#!/usr/bin/env python3
from setuptools import setup


__version__ = '0.0.1'


setup(name='mdec-binja',
	  version=__version__,
	  description='mdec-binja',
	  packages=['mdecbinja'],
	  install_requires=['aiohttp'],
	  python_requires='>=3.6'
	  )
