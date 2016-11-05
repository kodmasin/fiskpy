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

from setuptools import setup, find_packages

setup(name = 'fisk',
      version = '0.8.1',
      description = "library for fiscalization (Hrvatska) as defined in wsdl-1.1.2 and wsdl-1.2",
      author = 'Boris Tomic',
      author_email = 'boris@kodmasin.net',
      packages=find_packages(),
      package_data={'fisk': ['CAcerts/*.pem']},
      install_requires = ['pyOpenSSL>=0.15.1', 'pycrypto>=2.5', 'requests>=2.10.0', 'signxml>=2.0.0'])