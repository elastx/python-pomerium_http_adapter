#!/usr/bin/env python3

import os

try:
    from setuptools import setup

except ImportError:
    from distutils.core import setup

version = '0.5'
source_directory = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(source_directory, 'README.md'), 'r') as file_handle:
    long_description = file_handle.read()

setup(
    name='pomerium_http_adapter',
    description='Transport adapter for requests to handle Pomerium authentication',
    long_description=long_description,
    long_description_content_type='text/markdown',
    keywords=['pomerium', 'requests', 'adapter'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Environment :: Plugins',
        'Topic :: Internet :: WWW/HTTP'],
    license='Apache License 2.0',
    author='Joel Rangsmo',
    author_email='joel.rangsmo@elastx.se',
    version=version,
    url='https://github.com/elastx/python-pomerium_http_adapter',
    download_url=(
        'https://github.com/elastx/python-pomerium_http_adapter/archive/v%s.tar.gz' % version),
    packages=['pomerium_http_adapter'],
    package_dir={'pomerium_http_adapter': 'pomerium_http_adapter'},
    install_requires=['requests>=2.23.0'])
