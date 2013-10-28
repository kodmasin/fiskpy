fisk.py - jednostavna implementacija biblioteke za fiskalizaciju
		  (Hrvatska) po wsdl-1.1.2
		  
REQUIREMENTS

1. pyXMLsec library - http://pyxmlsec.labs.libre-entreprise.org/
2. pyCrypto library - https://www.dlitz.net/software/pycrypto/

USAGE

1) Echo Request

```Python
import fisk
import xml.etree.ElementTree as et

#test echo 
echo = fisk.EchoRequest("Proba echo poruke")
echoSOAPMessage = echo.getSOAPMessage()

#print request message
print et.tostring(echoSOAPMessage)

#send request and print server reply
print et.tostring(echo.send())
```

2) PoslovniProstor Request

```Python
import fisk
import xml.etree.ElementTree as et
from datetime import date, timedelta

#create object needed for signing and verifing xml messages 
signer = fisk.FiskXMLsec('/path/to/your/key.pem', "kaypassword", '/path/to/your/cert.pem', ['/path/to/porezna/rootcert/democacert.pem'])
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

#poslovni prostor zahtjev
ppz = fisk.PoslovniProstorZahtjev(pp)

#print request message
print et.tostring(ppz.getSOAPMessage())

#send request message to server (DEMO) and print reply
print et.tostring(ppz.send(signer))
```

3) Racun Request

```Python
import fisk
import xml.etree.ElementTree as et
from datetime import date, timedelta

#create object needed for signing and verifing xml messages 
signer = fisk.FiskXMLsec('/path/to/your/key.pem', "kaypassword", '/path/to/your/cert.pem', ['/path/to/porezna/rootcert/democacert.pem'])

racun = fisk.Racun(data = {"Oib": "12345678901",
              "USustPdv": "true",
              "DatVrijeme": "26.10.2013T23:50:00",
              "OznSlijed": "P",
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
              "SpecNamj": "Tekst specijalne namjne"},
              keyFileName = '/path/to/your/key.pem')

#Zastitni kod is calculated so print it
print racun.ZastKod

#print generated message
print et.tostring(racun.generate())

#change one variable and check new zastitni kod and print message
racun.IznosUkupno = "1233.00"
print racun.ZastKod
print et.tostring(racun.generate())

#create Request and send it to server (DEMO) and print reply
racunZahtjev = fisk.RacunZahtjev(racun)
print et.tostring(racunZahtjev.send(signer))
```
