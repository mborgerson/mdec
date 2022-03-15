#!/usr/bin/env python3
from setuptools import setup


__version__ = '0.0.1'


setup(name='mdec-hexrays',
	  version=__version__,
	  description='mdec-hexrays',
	  packages=['mdechexrays'],
	  install_requires=['mdec-base'],
	  python_requires='>=3.6'
	  )
