"""A setuptools based setup module.

See:
https://packaging.python.org/en/latest/distributing.html
https://github.com/pypa/sampleproject
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
