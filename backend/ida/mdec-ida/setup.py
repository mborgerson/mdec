#!/usr/bin/env python3
from setuptools import setup


__version__ = '0.0.1'


setup(name='mdec-ida',
	  version=__version__,
	  description='mdec-ida',
	  packages=['mdecida'],
	  install_requires=['mdec-base'],
	  python_requires='>=3.6'
	  )
