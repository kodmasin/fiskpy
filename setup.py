# coding=UTF-8
"""
setup.py for fisk.py - simple library for
          fiscalization (Hrvatska)

Copyright 2013 Boris Tomić <boris@kodmasin.net>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

# Always prefer setuptools over distutils
from setuptools import find_packages, setup
# To use a consistent encoding
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='fisk',
    version='0.8.2',
    description="library for fiscalization (Hrvatska) as defined in wsdl-1.1.2 and wsdl-1.2",
    long_description=long_description,
    url='https://github.com/kodmasin/fiskpy',
    author='Boris Tomic',
    author_email='boris@kodmasin.net',
    license='Apache Software License',
    keywords='fiscalization tax',
    packages=find_packages(exclude=['contrib', 'docs', 'tests']),
    package_data={'fisk': ['CAcerts/*.pem']},
    install_requires=[
        'pyOpenSSL>=0.15.1',
        'pycrypto>=2.5',
        'requests>=2.10.0',
        'signxml>=2.0.0',
        'pyasn1>=0.2.2',
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'Intended Audience :: Financial and Insurance Industry',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Natural Language :: Croatian',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Office/Business :: Financial :: Accounting',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
)
