fiskpy
------

EN: *A simple fiscalization library for fiscalizing the receipts to the Croatian tax service.*

HR: *Biblioteka za fiskalizaciju računa Poreznoj upravi Republike Hrvatske.*

**Note1:** This library is not Python 3 compatible.

INSTALLATION
------------

To install this package from PyPI, use the following command:

.. code:: bash

    $ pip install fisk

REQUIREMENTS
------------

1. signxml - pip install signxml (version 2 supported from fiskpy
   v0.8.1)
2. pyCrypto library - https://www.dlitz.net/software/pycrypto/

USAGE
-----

Echo Request
~~~~~~~~~~~~

.. code:: python

    import fisk
    import lxml.etree as et

    #As we did not set environment with FiskInit default environment is DEMO. This
    #works just with EchoRequest as it does not require key (with password) and certificate.

    #test echo
    echo = fisk.EchoRequest("Proba echo poruke")

    #send request and print server reply
    echo_reply = echo.execute()
    if(echo_reply != False):
        print echo_reply
    else:
        errors = echo.get_last_error()
        print "EchoRequest errors:"
        for error in errors:
            print error

PoslovniProstor Request
~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

    import fisk
    import lxml.etree as et
    from datetime import date, timedelta

    #fiskpy initialization !!! must be used for PoslovniProstorZahtjev
    fisk.FiskInit.init('/path/to/your/key.pem', "kaypassword", '/path/to/your/cert.pem')
    #For production environment
    #fisk.FiskInit.init('/path/to/your/key.pem', "kaypassword", '/path/to/your/cert.pem', Ture)
    #create addres
    adresa = fisk.Adresa(data = {"Ulica": "Proba", "KucniBroj": "1", "BrojPoste": "54321"})
    #create poslovni prostor
    pp = fisk.PoslovniProstor(data = {"Oib": "12345678901",
                                 "OznPoslProstora": "POS1",
                                 "AdresniPodatak": fisk.AdresniPodatak(adresa),
                                 "RadnoVrijeme": "PON-PET 9:00-17:00",
                                 "DatumPocetkaPrimjene": (date.today() + timedelta(days = 1)).strftime('%d.%m.%Y')})

    #you can also access (set and get) attributes of fisk element classes as
    pp.SpecNamj = "12345678901"
    print pp.OznPoslProstora

    #poslovni prostor request
    ppz = fisk.PoslovniProstorZahtjev(pp)

    ppz_reply = ppz.execute()
    if(ppz_reply == True):
        print "PoslovniProstorZahtjev seccessfuly sent!"
    else:
        errors = ppz.get_last_error()
        print "PoslovniProstorZahtjev reply errors:"
        for error in errors:
            print error

    #fiskpy deinitialization - maybe not needed but good for correct garbage cleaning
    fisk.FiskInit.deinit()

Racun Request
-------------

.. code:: python

    import fisk
    import lxml.etree as et
    from datetime import date, timedelta

    #fiskpy initialization !!! must be used for RacunZahtjev
    fisk.FiskInit.init('/path/to/your/key.pem', "kaypassword", '/path/to/your/cert.pem')
    #For production environment
    #fisk.FiskInit.init('/path/to/your/key.pem', "kaypassword", '/path/to/your/cert.pem', Ture)

    racun = fisk.Racun(data = {"Oib": "12345678901",
                  "USustPdv": "true",
                  "DatVrijeme": "26.10.2013T23:50:00",
                  "BrRac": fisk.BrRac({"BrOznRac": "2", "OznPosPr":"POS2", "OznNapUr":"1"}),
                  "Pdv": [fisk.Porez({"Stopa":"25.00", "Osnovica":"100.00", "Iznos":"25.00"}), fisk.Porez({"Stopa":"10.00", "Osnovica":"100.00", "Iznos":"10.00"})],
                  "Pnp": [fisk.Porez({"Stopa":"25.00", "Osnovica":"100.00", "Iznos":"25.00"}), fisk.Porez({"Stopa":"10.00", "Osnovica":"100.00", "Iznos":"10.00"})],
                  "OstaliPor": [fisk.OstPorez({"Naziv": "Neki porez",  "Stopa":"3.00", "Osnovica":"100.00", "Iznos":"3.00"})],
                  "IznosOslobPdv": "100.00",
                  "IznosMarza": "100.00",
                  "IznosNePodlOpor": "50.00",
                  "Naknade": [fisk.Naknada({"NazivN" : "test", "IznosN": "10.00"})],
                  "IznosUkupno": "500.00",
                  "NacinPlac": "G",
                  "OibOper": "12345678901",
                  "NakDost": "false",
                  "ParagonBrRac": "123-234-12",
                  "SpecNamj": "Tekst specijalne namjne"})

    #IWe did not supplied required element in constructor so now we set it
    racun.OznSlijed = "P"

    #Zastitni kod is calculated so print it
    print "ZKI: " + racun.ZastKod

    #change one variable and check new zastitni kod
    racun.IznosUkupno = "1233.00"
    print "ZKI: " + racun.ZastKod

    #create Request and send it to server (DEMO) and print reply
    racunZahtjev = fisk.RacunZahtjev(racun)
    racun_reply = racunZahtjev.execute()
    if(racun_reply != False):
        print "JIR is: " + racun_reply
    else:
        errors = racunZahtjev.get_last_error()
        print "RacunZahtjev reply errors:"
        for error in errors:
            print error

    #fiskpy deinitialization - maybe not needed but good for correct garbage cleaning
    fisk.FiskInit.deinit()

Provjera Request
----------------

.. code:: python

    import fisk
    from lxml import etree as et
    from datetime import date, timedelta

    #fiskpy initialization
    fisk.FiskInit.init('/path/to/your/key.pem', "kaypassword", '/path/to/your/cert.pem')

    racun = fisk.Racun(data = {"Oib": "12345678901",
                "USustPdv": "true",
                "DatVrijeme": "26.10.2013T23:50:00",
                "BrRac": fisk.BrRac({"BrOznRac": "2", "OznPosPr":"POS2", "OznNapUr":"1"}),
                "Pdv": [fisk.Porez({"Stopa":"25.00", "Osnovica":"100.00", "Iznos":"25.00"}), fisk.Porez({"Stopa":"10.00", "Osnovica":"100.00", "Iznos":"10.00"})],
                "Pnp": [fisk.Porez({"Stopa":"25.00", "Osnovica":"100.00", "Iznos":"25.00"}), fisk.Porez({"Stopa":"10.00", "Osnovica":"100.00", "Iznos":"10.00"})],
                "OstaliPor": [fisk.OstPorez({"Naziv": "Neki porez",  "Stopa":"3.00", "Osnovica":"100.00", "Iznos":"3.00"})],
                "IznosOslobPdv": "100.00",
                "IznosMarza": "100.00",
                "IznosNePodlOpor": "50.00",
                "Naknade": [fisk.Naknada({"NazivN" : "test", "IznosN": "10.00"})],
                "IznosUkupno": "500.00",
                "NacinPlac": "G",
                "OibOper": "12345678901",
                "NakDost": "false",
                "ParagonBrRac": "123-234-12",
                "SpecNamj": "Tekst specijalne namjne"})

    #We did not supplied required element in constructor so now we set it
    racun.OznSlijed = "P"

    #Zastitni kod is calculated so print it
    print "ZKI: " + racun.ZastKod

    #change one variable and check new zastitni kod
    racun.IznosUkupno = "1233.00"
    print "ZKI :" + racun.ZastKod

    #create Request and send it to server (DEMO) and print reply
    provjeraZahtjev = fisk.ProvjeraZahtjev(racun)
    provjera_reply = provjeraZahtjev.execute()

    if(provjera_reply == False):
      print "Request and response data is not the same"
    elif(isinstance(provjera_reply, et._Element)):
      for greska in provjera_reply:
        print u"Code: {} -> Message: {}".format(greska[0].text, greska[1].text)
    else:
      print("Unhandled error")

KEY GENERATION
--------------

Fiscalization keys and certificates are delivered in .p12 or .pfx
format. To be used with this library you should convert them to .pem
format. This can be done with openssl.

.. code:: bash

    $ openssl pkcs12 -in certificate.pfx -out certificate.pem -nodes

Now certificate.pem holds both key and certificate. So you should
manually open this file and copy each to separate file including
BEGIN/END statements.

Private key should be encrypted so if it is not you should run:

.. code:: bash

    $ openssl rsa -in key.pem -des3 -out passkey.pem

CA Certificates
~~~~~~~~~~~~~~~

Version >= 0.7.4
^^^^^^^^^^^^^^^^

CA certificate are included in release. You do should not supply them to
FiskInit class.

Versions < 0.7.4
^^^^^^^^^^^^^^^^

You will also need CA certificate for DEMO and PRODUCTION environment.
This certificate is needed for verification process.

DEMO CA Certificate
'''''''''''''''''''

You can download this certificate
https://demo-pki.fina.hr/crl/democacert.cer

DEMO CA 2014 Certificate (2 of them)
''''''''''''''''''''''''''''''''''''

You can download this certificates
http://www.fina.hr/Default.aspx?sec=1730

But in time of writing this you have to include old DEMO CA certificate
in list too, to work.

PRODUCTION CA Certificate
^^^^^^^^^^^^^^^^^^^^^^^^^

You can download them from http://www.fina.hr/Default.aspx?art=10758

Troubleshooting
^^^^^^^^^^^^^^^

**500: Internal Server Error** - this was bug before version 0.7.5

**ValueError: RSA key format is not supported** - this error could
happen if your private key is not encrypted. Please check if your
private key is encrypted. If it is not please encrypt it (''openssl rsa
-in key.pem -des3 -out passkey.pem'')
