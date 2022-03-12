#!/usr/bin/env python3
from setuptools import setup


__version__ = '0.0.1'


setup(name='mdec-base',
	  version=__version__,
	  description='mdec-base',
	  packages=['mdecbase'],
	  install_requires=['aiohttp'],
	  python_requires='>=3.6'
	  )
