#!/usr/bin/env python3
from setuptools import setup


__version__ = '0.0.1'


setup(name='mdec-angr',
	  version=__version__,
	  description='mdec-angr',
	  packages=['mdecangr'],
	  install_requires=['mdec-base', 'angr'],
	  python_requires='>=3.6'
	  )
