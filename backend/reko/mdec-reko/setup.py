#!/usr/bin/env python3
from setuptools import setup


__version__ = '0.0.1'


setup(name='mdec-reko',
	  version=__version__,
	  description='mdec-reko',
	  packages=['mdecreko'],
	  install_requires=['mdec-base'],
	  python_requires='>=3.6'
	  )
