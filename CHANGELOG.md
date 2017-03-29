# Changelog

## Version 0.8.2

- Update setup.py (dependencies, classifiers)
- Add CHANGELOG.rst
- Convert README.md to README.rst

## Version 0.8.1

- WSDL 1.3 support added (ProvjeraRacuna - can be used just in test environment - cistest.apis-it.hr)
- removed manually added certificate data in signXML

## Version 0.8.1 RC

- signxml 2 support
- better handeling of SOAP errors
- nicer and probably faster lxml usage

## Version 0.8.0

- switch from pyxmlsec to signxml
- FiksInit class changes, not back compatible
- small change in setup.py - now using setuputils

## Version 0.7.5

- Bug - response object with errors not handeled correctly, instead only http error 500: Internal Server Error was returned - fixed using requests module

## Version 0.7.4

- FINA CA certificates packed in release
- FiskInit - upgraded to use packed FINA certificates

## Version 0.7.3

- python 2.7.9 support moved to master branch

## Version 0.7.2

- files reorganization to distribute CA certificates together with code - needed for python version above 2.7.8 version

## Version 0.7.1

- using urllib instead of httplib

## Version 0.7.0

- FiskInit class for easier certificates and password handling

## Version 0.6.3

- fixed bug with encrypted keys
- fixed small bug with text part of Element class related to unicode

## Version 0.6.2

- added FiskSOAPClientProduction helper class
- EchoRequest unicode bug fixed

## Version 0.6.1

- added type information in Validation errors / exceptions
- Exception handling removed from execute method - you have to except them by your self
- implemented get_id_mag and get_datetime_msg methods of FiskXMLRequest class
- PoslovniProstorZahtjev execute method false true bug fixed
- unicode support for 2.x python fixed (I hope)

## Version 0.6

- Known bugs fixed
- added execute method to FiskXMLRequest for easier request handling (no more need to parse raw XML returned from server and better error handling). execute method is similar to send method but it parses reply and returns reply as str or False if error occurs. There is also new get_last_error method for accessing possible errors.
- USAGE section in README now have examples using execute method instead send method. Send method still works as it is used internally
- little better handling of connection errors of FiskSOAPClient
- Fisk*Error classes used for exceptions - implementation changed

## Version 0.5.1

- Known bugs fixed
- required element check moved to generate method. So required element is check before sending request not at constructor.

## Version 0.5

First public release
