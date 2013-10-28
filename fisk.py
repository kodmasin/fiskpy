# coding=UTF-8
"""
fisk.py - jednostavna implementacija biblioteke za
          fiskalizaciju (Hrvatska) po wsdl-1.1.2

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

VERSION = 0.1 - samo testirano u DEMO okruzenju 
"""

from uuid import uuid4
from datetime import datetime
from xml.etree.ElementTree import Element, SubElement, tostring,\
     fromstring
from httplib import HTTPSConnection
import libxml2
import xmlsec
import re
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA, MD5
from Crypto.PublicKey import RSA

class XMLValidator:
    """
    base validator class
    """
    def validate(self, value):
        return True
    
class XMLValidatorLen(XMLValidator):
    """
    validator koji provjerava da li je duljina stringa u 
    danom rasponu izmedu min_len i max_len
    """
    def __init__(self, min_len, max_len):
        self.min = min_len
        self.max = max_len
    def validate(self, value):
        if(value == None):
            return True
        if (type(value) == str):
            lenght = len(value)
            if(lenght >=self.min and lenght <=self.max):
                return True
        return False
    
class XMLValidatorRegEx(XMLValidator):
    """
    regex validator
    """
    def __init__(self, regex):
        """
        regex je regular expression
        """
        self.regex = re.compile(regex)
    def validate(self, value):
        if(value == None):
            return True
        if (type(value) == str):
            if(self.regex.match(value) != None):
                return True
        return False
    
class XMLValidatorEnum(XMLValidator):
    """
    validator koji provjerava da li je vrijednost jedna od dostavljenih
    """
    def __init__(self, values):
        """
        values je lista dozvoljenih vrijednosti
        """
        self.values = values
    def validate(self, value):
        if(value == None):
            return True
        if(type(value) == str):
            if(value in self.values):
                return True
        return False           

class XMLValidatorType(XMLValidator):
    """
    provjerava da li je vrijednost objekt zadane klase
    """
    def __init__(self, typeC):
        """
        typeC je klasa koje mora biti objekt
        """
        self.type = typeC
    def validate(self, value):
        if(value == None):
            return True
        if(isinstance(value, self.type)):
            return True
        return False
    
class XMLValidatorListType(XMLValidator):
    """
    da li je vrijednost lista objekata odredenog tipa
    """
    def __init__(self, typeC):
        """
        typeC - tip objekta (class) koji sadrži lista 
        """
        self.type = typeC
    def validate(self, value):
        if(value == None):
            return True
        if(type(value) == list):
            ret = True
            for val in value:
                if(not isinstance(val, self.type)):
                    ret = False
                    break
            return ret
        return False
    
class XMLValidatorRequired(XMLValidator):
    """
    da li je vrijednost zahtjevana (ne moze biti None)
    """
    def validate(self, value):
        if(value == None):
            return False
        return True
        

class XMLElement(object):
    """
    XMLElement - generalni element koji se zna prikazati kao xml string
    
    generlano se koristi kao bazna kalsa
    """
    def __init__(self, childrenNames = None, namespace = "", text = "", data = None, name = None):
        """
        stvara XMLElement - koristi se za jednostavnije generiranje xml-a iz samih python klasa
        
        koristi ElementTree
        
        childrenNames - dict keys su moguca imena (tagova) koji mogu biti child node (element) a value
            je lista validatora
        namespace - namespace koji ce se koristiti za ovaj element i sve child element
        text - ako se postavi i ako se ne postavi niti jedan element ovaj element sadzi samo taj text
        data - dict() sa inicijalnim podacima
        name - if for some reason you have to use diferent name for xml tag then class name
        """
        if childrenNames == None:
            childrenNames = ()
        self.__dict__['items'] = dict()
        self.__dict__['order'] = []
        self.__dict__['attributes'] = dict()
        self.__dict__['namespace'] = "{" + namespace + "}"
        self.__dict__['textValidators'] = []
        self.__dict__['name'] = name
        self.__dict__["validators"] = dict()
        self.setAvailableChildren(childrenNames.keys())
        
        for key, validator in childrenNames.items():
            if(key == "text"):
                if(type(validator) == list):
                    self.__dict__["textValidators"] = validator
                else:
                    raise TypeError("Validators has to be list of validators")
            else:
                if key in self.__dict__['order']:
                    if(type(validator) == list):
                        self.__dict__["validators"][key] = validator
                    else:
                        raise TypeError("Validators has to be list of validators")
                
        if text != "":
            self.text = text   
        if data != None:
            for key in self.__dict__['order']:
                if(key in data):
                    value = data[key]
                    self.__setattr__(key, value)
                else:
                    self.__setattr__(key, None) 

        
    def generate(self):
        """
        vraca Element (iz ElementTree) koji je u biti reprezentacija generiranog elemnta
        """
       
        xml = Element(self.__dict__["namespace"] + self.getName(), self.__dict__['attributes'])
        if self.__dict__['items']:
            for key in self.__dict__['order']:
                value = self.__dict__['items'][key] 
                if value != None:
                    if(type(value) is str):
                        svar = SubElement(xml, self.__dict__["namespace"] + key)
                        svar.text = value
                    elif(type(value) is list):
                        svar = SubElement(xml, self.__dict__["namespace"] + key)
                        for subvalue in value:
                            if(issubclass(type(subvalue), XMLElement)):
                                svar.append(subvalue.generate())
                    elif(issubclass(type(value), XMLElement) and key == value.getName()):
                        xml.append(value.generate())
                    else:
                        raise TypeError
        else:
            xml.text = self.__dict__["text"]
        return xml
    
    
    def __getattr__(self, name):
        if name not in self.items:
            raise NameError
        return self.items[name]
    
    def __setattr__(self, name, value):
        if name == "items":
            return
        if(name == "text"):
            if(type(value) == str):
                if(self._validateValue(name, value)):
                    self.__dict__['items'] = dict()
                    self.__dict__['text'] = value
                else:
                    ValueError("Value " + value + " is not valid as text of " + self.__class__.__name__ + " element")
            else:
                raise TypeError("text attribute must be string")
        else:
            if name not in self.__dict__['order']:
                raise NameError("This class does not have attribute with given name")
            if(self._validateValue(name, value)):  
                self.items[name] = value
            else:
                raise ValueError("Value " + str(value) + " is not valid for " + name + " attribute of class " + self.__class__.__name__)
        
    def setAvailableChildren(self, attrs, force = False):
        """
        postavlja listu mogucih child elemenata
        
        force - Boolean - True ako resetira postojecu listu
            False - ako zelimo da ju postavi samo ako je postojeca
            lista prazna
        """
        if force:
            self.__dict__['items'] = dict()
            self.__dict__['order'] = []
            self.__dict__['validators'] = dict()
        if(not self.__dict__['order']):
            for attr in attrs:
                if attr != "text":
                    self.__dict__['items'][children] = None
                    self.__dict__['order'].append(attr)
                    self.__dict__['validators'][attr] = []
            
    def setAttr(self, attrs):
        """
        postavla xml attribute samog elementa
        """
        if(type(attrs), dict):
            self.__dict__['attributes'] = attrs
            
    def setNamespace(self, namespace):
        """
        postavlja novi namespace u kojem spadaju ovaj element i sva njegova string djeca
        """
        self.__dict__["namespace"] = "{" + namespace + "}"
    
    def getElementName(self):
        """
        vraca puno ime elementa ukljucujuci u namespace u ElementTree fromatu
        """
        return self.__dict__["namespace"] + self.getName()
        
    def getName(self):
        name = self.__class__.__name__
        if self.__dict__['name'] != None :
            name = self.__dict__['name']
        return name

    def addValidator(self, name, validator):
        """
        adds new validator to valirable.
        
        After adding new validator this function will try to validate element
        """
        if(name == "text"):
            if(isinstance(validator, XMLValidator)):
                self.__dict__["textValidators"].append(validator)
                if(not self._validateValue(name, self.__dict__["items"][name])):
                    raise ValueError("Value " + self.__dict__["items"][name] + " is not valid for " + name + " attribute of class " + self.__class__.__name__)
        else:
            if(name not in self.__dict__["order"]):
                raise NameError("This object does not have attribute with given value")
            if(isinstance(validator, XMLValidator)):
                if(self.__dict__["validators"][name]):
                    self.__dict__["validators"][name].append(validator)
                else:
                    self.__dict__["validators"][name] = []
                    self.__dict__["validators"][name].append(validator)
                if(not self._validateValue(name, self.__dict__["items"][name])):
                    raise ValueError("Value " + self.__dict__["items"][name] + " is not valid for " + name + " attribute of class " + self.__class__.__name__)
            else:
                raise TypeError("validator has to be instance or subclass of XMLValidator")
        
    def _validateValue(self, name, value):
        """
        Private method to validate class attribute with avaliable validators 
        """
        if(name == "text"):
            if(type(value) == str):
                for validator in self.__dict__["textValidators"]:
                    if(not validator.validate(value)):
                        return False
        else:
            if(name not in self.__dict__["order"]):
                raise NameError("This object does not have attribute with given value")
            
            for validator in self.__dict__['validators'][name]:
                if(not validator.validate(value)):
                    return False
        return True
        
        
class FiskXMLEleSignerError(Exception):
    """
    exception koja je koristena u FiksXMLsec objektu
    """
    def __init__(self, value):
        self.value = value
    
    def __str__(self):
        return repr(self.value)
    

class FiskXMLsec(object):
    """
    klasa koja implementira potpisivanje xml dokumenta odnoso tocnije
    xml fiskal poruka
    
    koristi pyXMLsec
    """
    def __init__(self, key, password, cert, trustcert = None):
        """
        stvara i inicira sve portebno za potpisivanje xml fiskalne poruke
        
        key - string - key file path. ova datoteka mora biti u pem formatu
        passwrod - string - password za otkljucavanje keyja
        cert - string - certificate file. ova datoteka mora biti u pem formatu
        trustcert - list of strings - imena fileova sa trusted certifikatima potrebnim za
            verifikaciju potpisa u pem formatu
        """
        
        if(trustcert == None):
            trustcert = []
        self.init_error = []
        self.key = None
        self.dsig_ctx = None
        self.mngr = None
        
        # Init libxml library
        libxml2.initParser()
        libxml2.substituteEntitiesDefault(1)
        
        # Init xmlsec library
        if xmlsec.init() < 0:
            self.init_error.append("xmlsec initialization failed.")
            
        # Check loaded library version
        if xmlsec.checkVersion() != 1:
            self.init_error.append("loaded xmlsec library version is not compatible.")
        
        # Init crypto library
        if xmlsec.cryptoAppInit(None) < 0:
            self.init_error.append("crypto initialization failed.")
        
        # Init xmlsec-crypto library
        if xmlsec.cryptoInit() < 0:
            self.init_error.append("xmlsec-crypto initialization failed.")
        #load key for signing
        self.key = xmlsec.cryptoAppKeyLoad(key, xmlsec.KeyDataFormatPem, password, None, None)
        if self.key == None:
            self.init_error.append("key in file " + key + " could not be loaded.")
        else:
            if(xmlsec.cryptoAppKeyCertLoad(self.key, cert, xmlsec.KeyDataFormatPem) < 0):
                self.init_error.append("Certificate in file " + cert + " could not be loaded.")
        #create key manager for keys for verification        
        self.mngr = xmlsec.KeysMngr()
        if self.mngr is None:
            self.init_error.append("Error: failed to create keys manager.")
        if xmlsec.cryptoAppDefaultKeysMngrInit(self.mngr) < 0:
            self.init_error.append("Error: failed to initialize keys manager.")
        for tcert in trustcert:
            if self.mngr.certLoad(tcert, xmlsec.KeyDataFormatPem,
                             xmlsec.KeyDataTypeTrusted) < 0:
                self.init_error.append("Error: failed to load pem certificate from:" + tcert)
                
    
    def __del__(self):
        """
        ciscenje
        """
        #delete kay
        if(self.key != None):
            self.key.destroy()
        if(self.mngr != None):
            self.mngr.destroy()
        # Shutdown xmlsec-crypto library
        xmlsec.cryptoShutdown()
        
        # Shutdown crypto library
        xmlsec.cryptoAppShutdown()
        
        # Shutdown xmlsec library
        xmlsec.shutdown()
        
        # Shutdown LibXML2
        libxml2.cleanupParser()
        
    
    def signTemplate(self, fiskXMLTemplate, elementToSign):
        """
        potpisuje predlozak (template) fiskalne poruke koju treba potpisati
        
        vraca xml string
        
        fiskXMLTemplate - Element (from ElementTree) xml template fisklane poruke koji ce se potpisati
        elementToSign - string - ime elementa (tag) unutar xml template fiskalne poruke koji treba potpisati
        """
        
        if(self.init_error):
            raise FiskXMLEleSignerError(self.init_error)
        
        root = fiskXMLTemplate
        
        RequestElement = None
        
        for child in root.iter(elementToSign):
            if(child.tag == elementToSign):
                RequestElement = child
                break
        
        if(RequestElement == None):
            raise FiskXMLEleSignerError("Coudl not find element to sign")
        
        #dodavanje Signature taga
        namespace = "{http://www.w3.org/2000/09/xmldsig#}"
        Signature = SubElement(RequestElement, namespace + "Signature")
        SignedInfo = SubElement(Signature, namespace + "SignedInfo")
        SubElement(SignedInfo, namespace + "CanonicalizationMethod", {"Algorithm": "http://www.w3.org/2001/10/xml-exc-c14n#"})
        SubElement(SignedInfo, namespace + "SignatureMethod", {"Algorithm": "http://www.w3.org/2000/09/xmldsig#rsa-sha1"})
        Reference = SubElement(SignedInfo, namespace + "Reference", {"URI": "#" + RequestElement.get("Id")})
        Transforms = SubElement(Reference, namespace + "Transforms")
        SubElement(Transforms, namespace + "Transform", {"Algorithm": "http://www.w3.org/2000/09/xmldsig#enveloped-signature"})
        SubElement(Transforms, namespace + "Transform", {"Algorithm": "http://www.w3.org/2001/10/xml-exc-c14n#"})
        SubElement(Reference, namespace + "DigestMethod", {"Algorithm": "http://www.w3.org/2000/09/xmldsig#sha1"})
        SubElement(Reference, namespace + "DigestValue")
        SubElement(Signature, namespace + "SignatureValue")
        KeyInfo = SubElement(Signature, namespace + "KeyInfo")
        X509Data = SubElement(KeyInfo, namespace + "X509Data")
        SubElement(X509Data, namespace + "X509Certificate")
        SubElement(X509Data, namespace + "X509IssuerSerial")
        #pretvaranje iz ElemenTree u string
        myxml = tostring(root, "UTF-8")
        #parsiranje stringa (
        doc = xmlsec.parseMemory(myxml, len(myxml), 1)
        #dohavanje Singature taga
        signNode = xmlsec.findNode(doc.getRootElement(), xmlsec.NodeSignature, xmlsec.DSigNs)
        #postavljenje vazeceg id atributa  
        xmlsec.addIDs(doc, doc.getRootElement(), ["Id"])
        
        dsig_ctx = xmlsec.DSigCtx()
        #we must copy key as otherwise it will be deleted on DSigCtx destroy
        ckey = xmlsec.Key()
        self.key.copy(ckey)
        dsig_ctx.signKey = ckey
        
        if (dsig_ctx.sign(signNode) < 0):
            raise FiskXMLEleSignerError("Coudl not sign xml data")
        
        if(dsig_ctx != None and isinstance(dsig_ctx, xmlsec.DSigCtx)):
            dsig_ctx.destroy()
        
        signedxml = doc.serialize('UTF-8')

        doc.freeDoc()
        return signedxml
    
    def verifiyXML(self, xml):
        """
        verificira dani xml dokument
        
        vraca True ako verifikacija uspije, False ako ne uspije
        """
        doc = xmlsec.parseMemory(xml, len(xml), 1)
        snode = xmlsec.findNode(doc.getRootElement(), xmlsec.NodeSignature, xmlsec.DSigNs)
        xmlsec.addIDs(doc, doc.getRootElement(), ["Id"])
        
        if snode is None:
            return False
        
        dsig_ctx = xmlsec.DSigCtx(self.mngr)
        
        if dsig_ctx.verify(snode) < 0:
            raise FiskXMLEleSignerError("Coudl not verify xml data")
        
        rvalue = False
        if dsig_ctx.status == xmlsec.DSigStatusSucceeded:
            rvalue = True
        
        if(dsig_ctx != None and isinstance(dsig_ctx, xmlsec.DSigCtx)):
            dsig_ctx.destroy()
            
        doc.freeDoc()
        return rvalue



class FiskSOAPMessage():
    """
    SOAP Envelope element
    
    postavlja SOAP elemente oko contenta
    """
    def __init__(self, content = None):
        """
        content - ElementTree objekt
        """
        namespace = "{http://schemas.xmlsoap.org/soap/envelope/}"
        self.message = Element(namespace + "Envelope")
        self.body = SubElement(self.message, namespace + "Body")
        if content != None:
            self.body.append(content.generate())
        
    def setBodyContent(self, content):
        """
        sets new SOAP message body content
        """
        self.body.clear()
        self.body.append(content.generate())
        
    def getSOAPMessage(self):
        """
        return ElementTree reprezentation of SOAPMEssage
        """
        return self.message
    

class FiskSOAPClient(object):
    """
    very simple SOAP Client implementation
    """
    def __init__(self, host = "cistest.apis-it.hr", port = "8449", url = "/FiskalizacijaServiceTest"):
        """
        construct client with service arguments (host, port, url)
        
        defaltni su postavljeni za testnu okolinu
        """
        self.host = host
        self.port = port
        self.url = url
    
    def send(self, message, raw = False):
        """
        send message (as xml string) to server
        
        returns ElementTree object with server response message
        
        if raw is True then returns raw xml
        """
        xml = message
        conn = HTTPSConnection(self.host, self.port)
        conn.request("POST", self.url, body=xml, headers = {
            "Host": "testing",
            "Content-Type": "text/xml; charset=UTF-8",
            "Content-Length": len(xml),
            "SOAPAction": "FiskalizacijaServiceTest"
        })
        
        response = conn.getresponse().read()
        if(not raw):
            response = fromstring(response)
        return response

    
        
        
class FiskXMLElement(XMLElement):
    """
    base element for creating fiskla xml messages
    """
    def __init__(self, childrenNames = None, text = "", data = None, name = None):
        XMLElement.__init__(self, childrenNames, "http://www.apis-it.hr/fin/2012/types/f73", text, data, name)

        
       

class FiskXMLRequest(FiskXMLElement):
    """
    base element for creating fiskal SOAP mesage
    
    it knows how to send request to srever using send
    """
    def __init__(self, childrenNames = None, text = "", data = None, name = None):
        FiskXMLElement.__init__(self, childrenNames, text, data)
        
    def getSOAPMessage(self):
        """
        adds SOAP elements to xml message
        """
        message = FiskSOAPMessage(self)
        return message.getSOAPMessage()
    
    def send(self, signer = None, SOAPclient = None):
        """
        send SOAP request to server
        """
        cl = SOAPclient
        if SOAPclient == None:
            cl = FiskSOAPClient()
        xml = self.getSOAPMessage()
        message = tostring(xml)
        
        if(signer != None and isinstance(signer, FiskXMLsec)):
            message = signer.signTemplate(xml, self.getElementName())
           
        reply = cl.send(message, True)
        if(signer != None and isinstance(signer, FiskXMLsec)):
            if(not signer.verifiyXML(reply)):
                reply = None
        if reply != None:
            reply = fromstring(reply)
        return reply
      
class EchoRequest(FiskXMLRequest):
    """
    EchoRequest fiskal element. On moze poslati EchoRequest SOAP poruku
    """
    def __init__(self, text=""):
        """
        stvara EchoRequest s tanim tekstom tekst moze biti izmedu 1 i 1000 znakova
        """
        FiskXMLRequest.__init__(self, text=text, childrenNames = {"text": [XMLValidatorLen(1,1000), XMLValidatorRequired()]})
        

class Zaglavlje(FiskXMLElement):
    """
    Zaglavlje fiskal element
    
    radi sam sve sto treba generira idPoruke (uuid4) i datum i vrijeme
    """
    def __init__(self):
        FiskXMLElement.__init__(self, childrenNames = {"IdPoruke": [XMLValidatorRegEx("^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")],
                                              "DatumVrijeme": [XMLValidatorRegEx("^[0-9]{2}.[0-9]{2}.[1-2][0-9]{3}T[0-9]{2}:[0-9]{2}:[0-9]{2}$")]})
        self.IdPoruke = str(uuid4())
        self.DatumVrijeme = datetime.now().strftime('%d.%m.%YT%H:%M:%S')
        self.addValidator("IdPoruke", XMLValidatorRequired())
        self.addValidator("DatumVrijeme", XMLValidatorRequired())
        
    def generate(self):#overide because we have to have new ID and time for every message we sent to porezna
        self.IdPoruke = str(uuid4())
        self.DatumVrijeme = datetime.now().strftime('%d.%m.%YT%H:%M:%S')
        return FiskXMLElement.generate(self)
        
class Adresa(FiskXMLElement):
    """
    Adresa fiskal element
    
    mozete postaviti slijedece attribute ovom elementu:
    Ulica, KucniBroj, KucniBrojDodatak, BrojPoste, Naselje, Opcina
    """
    def __init__(self, data = None):
        string35Val = XMLValidatorLen(1,35)
        FiskXMLElement.__init__(self,
                                childrenNames = {"Ulica": [XMLValidatorLen(1,100)],
                                              "KucniBroj" : [XMLValidatorRegEx("^\d{1,4}$")],
                                              "KucniBrojDodatak": [XMLValidatorLen(1,4)],
                                              "BrojPoste": [XMLValidatorRegEx("^\d{1,12}$")],
                                              "Naselje" : [string35Val],
                                              "Opcina" : [string35Val]
                                              },
                                data = data)
    
    
class AdresniPodatak(FiskXMLElement):
    """
    AdresniPodatak fiskal element
    
    mozete postaviti slijedece attribute ovom elementu:
    adresa - moze bit ili Adresa element ili string (za OstaliTipoviPP) 
    """
    def __init__(self, adresa):
        FiskXMLElement.__init__(self)
        if(isinstance(adresa, Adresa)):
            self.setAvailableChildren(("Adresa",))
            self.addValidator("Adresa", XMLValidatorType(Adresa))
            self.Adresa = adresa
        else:
            self.setAvailableChildren(("OstaliTipoviPP",))
            self.addValidator("OstaliTipoviPP", XMLValidatorLen(1,100))
            self.OstaliTipoviPP = adresa


class PoslovniProstor(FiskXMLElement):
    """
    Adresa fiskal element
    
    mozete postaviti slijedece attribute ovom elementu:
    Oib, OznPoslProstora, AdresniPodatak, RadnoVrijeme, DatumPocetkaPrimjene, OznakaZatvaranja, SpecNamj
    """
    def __init__(self, data = None):
        string1000Val = XMLValidatorLen(1,1000)
        FiskXMLElement.__init__(self, childrenNames = {"Oib": [XMLValidatorRegEx("^\d{11}$"), XMLValidatorRequired()],
                                              "OznPoslProstora": [XMLValidatorRegEx("^[0-9a-zA-Z]{1,20}$"), XMLValidatorRequired()],
                                              "AdresinPodatak" : [XMLValidatorType(Adresa), XMLValidatorRequired()],
                                              "RadnoVrijeme" : [string1000Val, XMLValidatorRequired()],
                                              "DatumPocetkaPrimjene": [XMLValidatorRegEx("^[0-9]{2}.[0-9]{2}.[1-2][0-9]{3}$"), XMLValidatorRequired()],
                                              "OznakaZatvaranja": [XMLValidatorEnum(["Z"])],
                                              "SpecNamj": [string1000Val]
                                              }, 
                                data = data)


class PoslovniProstorZahtjev(FiskXMLRequest):
    """
    PoslovniProstorZahtjev element. Ova klasa moze poslati SOAP message sa PoslovniProstorZahtjev-om te verificirati
    rezultat
    """
    def __init__(self, poslovniProstor):
        FiskXMLRequest.__init__(self, childrenNames = {"Zaglavlje": [XMLValidatorType(Zaglavlje)],
                                              "PoslovniProstor": [XMLValidatorType(PoslovniProstor), XMLValidatorRequired()]},
                                data = {"PoslovniProstor": poslovniProstor})
        self.Zaglavlje = Zaglavlje()
        self.setAttr({"Id": "ppz"})
        self.addValidator("Zaglavlje", XMLValidatorRequired())
        
class BrRac(FiskXMLElement):
    """
    BrojRacuna element
    """
    def __init__(self, data = None):
        regexVal = XMLValidatorRegEx("^\d{1,20}$")
        FiskXMLElement.__init__(self, childrenNames = {"BrOznRac" : [regexVal, XMLValidatorRequired()],
                                              "OznPosPr" : [XMLValidatorRegEx("^[0-9a-zA-Z]{1,20}$"), XMLValidatorRequired()],
                                              "OznNapUr" : [regexVal, XMLValidatorRequired()]}, 
                                data = data)
    
class Porez(FiskXMLElement):
    """
    Porez element
    """
    def __init__(self, data = None):
        regexVal = XMLValidatorRegEx("^([+-]?)[0-9]{1,15}\.[0-9]{2}$")
        FiskXMLElement.__init__(self, childrenNames = {"Stopa" : [XMLValidatorRegEx("^([+-]?)[0-9]{1,3}\.[0-9]{2}$"), XMLValidatorRequired()],
                                              "Osnovica" : [regexVal, XMLValidatorRequired()],
                                              "Iznos" : [regexVal, XMLValidatorRequired()]},
                                data = data)
        
class OstPorez(FiskXMLElement):
    """
    Porez element koji je dio OstaliPorezi elementa
    """
    def __init__(self, data = None):
        regexVal = XMLValidatorRegEx("^([+-]?)[0-9]{1,15}\.[0-9]{2}$")
        FiskXMLElement.__init__(self, childrenNames = {"Naziv" : [XMLValidatorLen(1,100), XMLValidatorRequired()],
                                              "Stopa" : [XMLValidatorRegEx("^([+-]?)[0-9]{1,3}\.[0-9]{2}$"), XMLValidatorRequired()],
                                              "Osnovica" : [regexVal, XMLValidatorRequired()],
                                              "Iznos" : [regexVal, XMLValidatorRequired()]},
                                data = data,
                                name = "Porez")

        
class Naknada(FiskXMLElement):
    """
    Naknada element
    """
    def __init__(self, data = None):
        FiskXMLElement.__init__(self, childrenNames = {"NazivN" : [XMLValidatorLen(1,100), XMLValidatorRequired()],
                                              "IznosN" : [XMLValidatorRegEx("^([+-]?)[0-9]{1,15}\.[0-9]{2}$"), XMLValidatorRequired()]},
                                data = data)


def zastitni_kod(oib, datumVrijeme, brRacuna, ozPoslovnogP, ozUredaja, ukupnoIznos, keyFilename):
    """
    generira zastitni kod za racun
    """
    forsigning = oib + datumVrijeme + brRacuna + ozPoslovnogP + ozUredaja + ukupnoIznos

    key = RSA.importKey(open(keyFilename).read())
    h = SHA.new(forsigning)
    signer = PKCS1_v1_5.new(key)
    signature = signer.sign(h)
    
    md5h = MD5.new()
    md5h.update(signature)
    return md5h.hexdigest()

class Racun(FiskXMLElement):
    """
    Racun element
    """
    def __init__(self, data, keyFileName):
        porezListVal = XMLValidatorListType(Porez)
        iznosVal = XMLValidatorRegEx("^([+-]?)[0-9]{1,15}\.[0-9]{2}$")
        oibVal = XMLValidatorRegEx("^\d{11}$")
        boolVal = XMLValidatorEnum(["true", "false"])
        FiskXMLElement.__init__(self, childrenNames = {"Oib": [oibVal, XMLValidatorRequired()],
                                       "USustPdv": [boolVal, XMLValidatorRequired()],
                                       "DatVrijeme": [XMLValidatorRegEx("^[0-9]{2}.[0-9]{2}.[1-2][0-9]{3}T[0-9]{2}:[0-9]{2}:[0-9]{2}$"), XMLValidatorRequired()],
                                       "OznSlijed": [XMLValidatorEnum(["P", "N"]), XMLValidatorRequired()],
                                       "BrRac": [XMLValidatorType(BrRac), XMLValidatorRequired()],
                                       "Pdv": [porezListVal],
                                       "Pnp": [porezListVal],
                                       "OstaliPor": [XMLValidatorListType(OstPorez)],
                                       "IznosOslobPdv": [iznosVal],
                                       "IznosMarza": [iznosVal],
                                       "IznosNePodlOpor": [iznosVal],
                                       "Naknade": [XMLValidatorListType(Naknada)],
                                       "IznosUkupno": [iznosVal, XMLValidatorRequired()],
                                       "NacinPlac": [XMLValidatorEnum(["G", "K", "C", "T", "O"]), XMLValidatorRequired()],
                                       "OibOper": [oibVal, XMLValidatorRequired()],
                                       "ZastKod": [XMLValidatorRegEx("^[a-f0-9]{32}$")],
                                       "NakDost": [boolVal, XMLValidatorRequired()],
                                       "ParagonBrRac": [XMLValidatorLen(1,100)],
                                       "SpecNamj": [XMLValidatorLen(1,1000)]},
                                data = data)
        self.__dict__["key"] = keyFileName
        self.__dict__["items"]["ZastKod"] = zastitni_kod(self.Oib,
                                    self.DatVrijeme,
                                    self.BrRac.BrOznRac,
                                    self.BrRac.OznPosPr,
                                    self.BrRac.OznNapUr,
                                    self.IznosUkupno,
                                    self.__dict__["key"])
        
    def __setattr__(self, name, value):
        """
        overiden so that it is not possible to set ZastKod and to update
        ZastKod is some of variables which are used to generate Zastkode are changed
        
        wanted to raise exception if someone want to set ZastKod but it is not possible 
        because of constructor
        """
        if(name != "ZastKod"):
            FiskXMLElement.__setattr__(self, name, value)
            if(name in ["Oib", "DatVrijeme", "BrRac", "IznosUkupno"]):
                if(self.Oib != None and self.DatVrijeme != None and self.BrRac != None and self.IznosUkupno != None and ("key" in self.__dict__)):
                    self.__dict__["items"]["ZastKod"] = zastitni_kod(self.Oib,
                                            self.DatVrijeme,
                                            self.BrRac.BrOznRac,
                                            self.BrRac.OznPosPr,
                                            self.BrRac.OznNapUr,
                                            self.IznosUkupno,
                                            self.__dict__["key"])

class RacunZahtjev(FiskXMLRequest):
    """
    RacunZahtijev element - ima sve sto treba da posalje racun na fiskalizaciju
    
    sam generira zastitni kod svaki put kada se promjeni neka od variabli
    koje sluze za njegovo generiranje
    """
    def __init__(self, racun):
        FiskXMLRequest.__init__(self, childrenNames = {"Zaglavlje": [XMLValidatorType(Zaglavlje)],
                                              "Racun": [XMLValidatorType(Racun), XMLValidatorRequired()]
                                              },
                                data = {"Racun": racun})
        self.Zaglavlje = Zaglavlje()
        self.setAttr({"Id": "rac"})
        self.addValidator("Zaglavlje", XMLValidatorRequired())
        
    