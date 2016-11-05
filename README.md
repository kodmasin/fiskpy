fisk.py - simple fiscalization (Fiskalizacija) library 
		  (Hrvatska)  

** !!! This is release candidate !!! **

**Note1:** Code is not working with python versions >= 3.0.0
**Note2:** Support for WSDL <= 1.2

## REQUIREMENTS

1. signxml - pip install signxml (version 2 supported from fiskpy v0.8.1)
2. pyCrypto library - https://www.dlitz.net/software/pycrypto/

## USAGE

### Echo Request

```Python
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
```

### PoslovniProstor Request

```Python
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
```

## Racun Request

```Python
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
```

## KEY GENERATION

Fiscalization keys and certificates are delivered in .p12 or .pfx format. To be used with this library you should
convert them to .pem format. This can be done with openssl.

```
openssl pkcs12 -in certificate.pfx -out certificate.pem -nodes
```

Now certificate.pem holds both key and certificate. So you should manually open this file and copy each to
separate file including BEGIN/END statements.

Private key should be encrypted so if it is not you should run:
```
openssl rsa -in key.pem -des3 -out passkey.pem
```

### CA Certificates
####Version >= 0.7.4

CA certificate are included in release. You do should not supply them to FiskInit class.

####Versions < 0.7.4

You will also need CA certificate for DEMO and PRODUCTION environment. This certificate is needed for
verification process.

##### DEMO CA Certificate

You can download this certificate https://demo-pki.fina.hr/crl/democacert.cer

##### DEMO CA 2014 Certificate (2 of them)

You can download this certificates http://www.fina.hr/Default.aspx?sec=1730

But in time of writing this you have to include old DEMO CA certificate in list too, to work.

#### PRODUCTION CA Certificate

You can download them from http://www.fina.hr/Default.aspx?art=10758
## Troubleshooting

**500: Internal Server Error** - this was bug before version 0.7.5

**ValueError: RSA key format is not supported** - this error could happen if your private key is not encrypted. Please check if your private key is encrypted. If it is not please encrypt it (''openssl rsa -in key.pem -des3 -out passkey.pem'')


## Changelog
### Version 0.8.1 RC
  * signxml 2 support
  * better handeling of SOAP errors
  * nicer and probably faster lxml usage

### Version 0.8.0
  * switch from pyxmlsec to signxml
  * FiksInit class changes, not back compatible
  * small change in setup.py - now using setuputils
  
### Version 0.7.5
  * Bug - response object with errors not handeled correctly, instead only http 
  error 500: Internal Server Error was returned - fixed using requests module

### Version 0.7.4
  * FINA CA certificates packed in release
  * FiskInit - upgraded to use packed FINA certificates

### Version 0.7.3
  * python 2.7.9 support moved to master branch

### Version 0.7.2
  * files reorganization to distribute CA certificates together with code - needed for python version above 2.7.8 version

### Version 0.7.1
  * using urllib instead of httplib

### Version 0.7.0
  * FiskInit class for easier certificates and password handling

### Version 0.6.3
  * fixed bug with encrypted keys
  * fixed small bug with text part of Element class related to unicode

### Version 0.6.2
  * added FiskSOAPClientProduction helper class
  * EchoRequest unicode bug fixed

### Version 0.6.1
  * added type information in Validation errors / exceptions
  * Exception handling removed from execute method - you have to except them by your self
  * implemented get_id_mag and get_datetime_msg methods of FiskXMLRequest class
  * PoslovniProstorZahtjev execute method false true bug fixed
  * unicode support for 2.x python fixed (I hope)

### Version 0.6
  * Known bugs fixed
  * added execute method to FiskXMLRequest for easier request handling (no more need to parse raw XML returned
  from server and better error handling). execute method is similar to send method but it parses reply and
  returns reply as str or False if error occurs. There is also new get_last_error method for accessing
  possible errors.
  * USAGE section in README now have examples using execute method instead send method. Send method still works
  as it is used internally
  * little better handling of connection errors of FiskSOAPClient
  * Fisk*Error classes used for exceptions - implementation changed

### Version 0.5.1

  * Known bugs fixed
  * required element check moved to generate method. So required element is check before sending request
  not at constructor. 

### Version 0.5

First public release 