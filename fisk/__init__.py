# -*- coding: utf-8 -*-

from uuid import uuid4
from datetime import datetime
from lxml import etree as et
import requests
from signxml import XMLSigner, XMLVerifier
from cryptography.exceptions import InvalidSignature
from OpenSSL.crypto import load_certificate, FILETYPE_PEM
import re
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA, MD5
from Crypto.PublicKey import RSA
import os

class XMLValidator:
    """
    base validator class
    """
    def validate(self, value):
        """

        """
        return True

class XMLValidatorLen(XMLValidator):
    """
    validator which check string lenght
    """
    def __init__(self, min_len, max_len):
        """
        Args:
            min_len (int): Minimum lenght
            max_len (int): Maximum length
        """
        self.min = min_len
        self.max = max_len

    def validate(self, value):
        if(value == None):
            return True
        if (type(value) == unicode or type(value) == str):
            lenght = len(value)
            if(lenght >=self.min and lenght <=self.max):
                return True
        return False

class XMLValidatorRegEx(XMLValidator):
    """
    regex validator. Returns True if regex is matched or false if it is not.
    """
    def __init__(self, regex):
        """
        Args:
            regex (str): is regular expression
        """
        if(type(regex) == unicode):
            self.regex = re.compile(regex, re.UNICODE)
        else:
            self.regex = re.compile(regex, re.UNICODE)
    def validate(self, value):
        if(value == None):
            return True
        if (type(value) == unicode or type(value) == str):
            if(self.regex.match(value) != None):
                return True
        return False

class XMLValidatorEnum(XMLValidator):
    """
    validator which checks is value in values list. Returns
    True if value is found in list and flase if value is ot in the list
    """
    def __init__(self, values):
        """
        Args:
            values (list): list of possible values
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
    type cheking validator
    """
    def __init__(self, typeC):
        """
        Args:
            typeC: is object of which type value should be checked.
        """
        self.type = typeC
    def validate(self, value):
        """
        Returns: True if value is not set or if value is of selected
            type otherwise returns False
        """
        if(value == None):
            return True
        if(isinstance(value, self.type)):
            return True
        return False

class XMLValidatorListType(XMLValidator):
    """
    validator which checks are all object in list of defined type.
    Returns True if they are False if they are not.
    """
    def __init__(self, typeC):
        """
        Args:
            typeC: tpye for which list itmes will be checked
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
    cheks is value None or not.
    """
    def validate(self, value):
        """
        Returns: True if value is not None or False
            if value is None
        """
        if(value == None):
            return False
        return True


class XMLElement(object):
    """
    XMLElement - this is class which knows to represent her self and hers attributes as xml element

    this is usually used as base calss

    it uses ElementTree for xml generation
    """
    def __init__(self, childrenNames = None, namespace = "", text = None, data = None, name = None):
        """
        creates XMLElement object

        childrenNames (tuple): ((name1, validators1), (name2, validators2), ...)
        namespace (str): xml namespace used for this class element and its sub elements
        text (str): if set and if this class does not hold any attribute that this text is text inside xml tag
        data (dict): initial data
        name (str): if for some reason you have to use diferent name for xml tag then class name
        """
        if childrenNames == None:
            childrenNames = ()
        self.__dict__['items'] = dict()
        self.__dict__['order'] = []
        self.__dict__['attributes'] = dict()
        self.__dict__['namespace'] = "{" + namespace + "}"
        self.__dict__['text'] = None
        self.__dict__['textValidators'] = []
        self.__dict__['textRequired'] = []
        self.__dict__['name'] = name
        self.__dict__["validators"] = dict()
        self.__dict__['required'] = dict()

        childNames = list()
        for element in childrenNames:
            key, value = element
            childNames.append(key)
        self.setAvailableChildren(childNames)

        for element in childrenNames:
            name, validators = element
            if(type(validators) == list):
                for validator in validators:
                    self.addValidator(name, validator)
            else:
                raise TypeError("Validators has to be list of validators")

        #self.addValidator('text', XMLValidatorType(str))

        if text != None:
            self.__setattr__("text", text)
        if data != None:
            for name, value in data.items():
                self.__setattr__(name, value)


    def generate(self):
        """
        Returns (ElementTree): xml reprezentation of this class

        Raises:
            ValueError: This method also checks are all required valuesa (attributes) set.
                If not it will raise this exception
        """
        #generate xml as ElementTree
        xml = et.Element(self.__dict__["namespace"] + self.getName(), self.__dict__['attributes'])
        if self.__dict__['items']:
            for key in self.__dict__['order']:
                #check if it is required
                if key in self.__dict__['required']:
                    validators = self.__dict__['required'][key]
                    for validator in validators:
                        if(not validator.validate(self.__dict__['items'][key])):
                            raise ValueError("Attribute " + key + " of class " + self.__class__.__name__ + " is required!")
                value = self.__dict__['items'][key]
                if value != None:
                    if(type(value) is str or type(value) is unicode):
                        svar = et.SubElement(xml, self.__dict__["namespace"] + key)
                        svar.text = value
                    elif(type(value) is list):
                        svar = et.SubElement(xml, self.__dict__["namespace"] + key)
                        for subvalue in value:
                            if(issubclass(type(subvalue), XMLElement)):
                                svar.append(subvalue.generate())
                    elif(issubclass(type(value), XMLElement) and key == value.getName()):
                        xml.append(value.generate())
                    else:
                        raise TypeError("Generate method in class " + self.__class__.__name__ + " can not generate supplied type")
        else:
            #check if it text is required
            validators = self.__dict__['textRequired']
            for validator in validators:
                if(not validator.validate(self.__dict__['text'])):
                    raise ValueError("Text attribute of class " + self.__class__.__name__ + " is required!")
            xml.text = self.__dict__["text"]
        return xml


    def __getattr__(self, name):
        if name not in self.items:
            raise NameError("Class " + self.__class__.__name__ + " does not have attribute with name " + name)
        return self.items[name]

    def __setattr__(self, name, value):
        if name == "items":
            return
        if(name == "text"):
            if(type(value) == str or type(value) == unicode):
                if(self._validateValue(name, value)):
                    self.__dict__['items'] = dict()
                    self.__dict__['text'] = value
                else:
                    ValueError("Value " + value + " (" + type(value).__name__ + ") is not valid as text of " + self.__class__.__name__ + " element")
            else:
                raise TypeError("text attribute must be string")
        else:
            if name not in self.__dict__['order']:
                raise NameError("Class " + self.__class__.__name__ + " does not have attribute with name " + name)
            if(self._validateValue(name, value)):
                self.items[name] = value
            else:
                raise ValueError("Value " + str(value) + " (" + type(value).__name__ + ") is not valid for " + name + " attribute of class " + self.__class__.__name__)

    def setAvailableChildren(self, names):
        """
        sets list of possible sub elements (in context of class possible attributes)

        """
        self.__dict__['items'] = dict()
        self.__dict__['order'] = []
        self.__dict__['validators'] = dict()
        self.__dict__['required'] = dict()
        for name in names:
            if name != "text":
                self.__dict__['items'][name] = None
                self.__dict__['order'].append(name)
                self.__dict__['validators'][name] = []
                self.__dict__['required'][name] = []

    def setAttr(self, attrs):
        """
        resets element attributes

        attrs - dict with keys as attribute names and values as attribure values
        """
        if(type(attrs), dict):
            self.__dict__['attributes'] = attrs

    def setNamespace(self, namespace):
        """
        set new namespace for this elementa and all his children
        """
        self.__dict__["namespace"] = "{" + namespace + "}"

    def getElementName(self):
        """
        returns full xml element tag name including namespace as used in
        ElementTree module
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
                if(isinstance(validator, XMLValidatorRequired)):
                    self.__dict__['textRequired'].append(validator)
                else:
                    self.__dict__["textValidators"].append(validator)
                    if(not self._validateValue(name, self.__dict__["text"])):
                        raise ValueError("Value " + self.__dict__["text"] + " (" + type(self.__dict__["text"]).__name__ + ") is not valid for " + name + " attribute of class " + self.__class__.__name__)
        else:
            if(name not in self.__dict__["order"]):
                raise NameError("This object does not have attribute with given value")
            if(isinstance(validator, XMLValidator)):
                #we separate required and value checkers because they are used in different places
                if(isinstance(validator, XMLValidatorRequired)):
                    if(not self.__dict__["required"][name]):
                        self.__dict__["required"][name] = []
                    self.__dict__["required"][name].append(validator)
                else:
                    if(not self.__dict__["validators"][name]):
                        self.__dict__["validators"][name] = []
                    self.__dict__["validators"][name].append(validator)

                    if(not self._validateValue(name, self.__dict__["items"][name])):
                        raise ValueError("Value " + self.__dict__["items"][name] + " (" + type(self.__dict__["items"][name]).__name__ + ") is not valid for " + name + " attribute of class " + self.__class__.__name__)
            else:
                raise TypeError("Validator for " + name + " attribute of " + self.__class__.__name__ + "class has to be instance or subclass of XMLValidator")

    def _validateValue(self, name, value):
        """
        Private method to validate class attribute with avaliable validators
        """
        if(name == "text"):
            for validator in self.__dict__["textValidators"]:
                if(not validator.validate(value)):
                    return False
        else:
            if(name not in self.__dict__["order"]):
                raise NameError("This object (of class " + self.__class__.__name__ + ") does not have attribute with given value")

            for validator in self.__dict__['validators'][name]:
                if(not validator.validate(value)):
                    return False
        return True


class FiskSOAPClientError(Exception):
    """
    exception used in FiskSOAPClient (and derived classes) class as indicator
    of some error
    """
    def __init__(self, message):
        Exception.__init__(self, message)

class FiskSOAPClient(object):
    """
    very very simple SOAP Client implementation
    """
    def __init__(self, host, port, url, verify = None):
        """
        construct client with service arguments (host, port, url, verify)

        verifiy - path to pem file with CA certificates for response verification
        """
        self.host = host
        self.port = port
        self.url = url
        self.verify = verify

    def send(self, message, raw = False):
        """
        send message (as xml string) to server

        returns ElementTree object with server response message

        if raw is True then returns raw xml
        """
        xml = message

        r = requests.post(r"https://" + self.host + r":" + self.port + self.url, headers = {
                "Host": self.host,
                "Content-Type": "text/xml; charset=UTF-8",
               # "Content-Length": len(xml),
                "SOAPAction": self.url
            }, data = xml, verify=self.verify)

        response = None
        if(r.status_code == requests.codes.ok):
            response = r.text
        else:
            if (r.headers['Content-Type']=="text/xml"):
                response = r.content
            else:
                raise FiskSOAPClientError(str(r.status_code) + ": " + r.reason)
        responseXML = et.fromstring(str(response))
        for relement in responseXML.iter():
                if(relement.tag.find("faultstring") != -1):
                    raise FiskSOAPClientError(relement.text)
        if(not raw):
            response = responseXML
        return response

class FiskSOAPClientDemo(FiskSOAPClient):
    """
    same class as FiskSOAPClient but with demo PU server parameters set by default
    """
    def __init__(self):
        mpath = os.path.dirname(__file__)
        cafile = mpath + "/CAcerts/demoCAfile.pem"
        FiskSOAPClient.__init__(self,
                                host = r"cistest.apis-it.hr",
                                port = r"8449",
                                url = r"/FiskalizacijaServiceTest",
                                verify = cafile)

class FiskSOAPClientProduction(FiskSOAPClient):
    """
    same class as FiskSOAPClient but with procudtion PU server parameters set by default
    """
    def __init__(self):
        mpath = os.path.dirname(__file__)
        cafile = mpath + "/CAcerts/prodCAfile.pem"
        FiskSOAPClient.__init__(self,
                                host = r"cis.porezna-uprava.hr",
                                port = r"8449",
                                url = r"/FiskalizacijaService",
                                verify = cafile)

class FiskXMLEleSignerError(Exception):
    """
    exception used in FiskXMLsec class as indicator
    of some error
    """
    def __init__(self, message):
        Exception.__init__(self, message)



class Signer(object):
    """
    class which implements signing of fiskal SOAP messages

    it uses signxml library for that purpose
    """

    def __init__(self, key, password, cert):
        """
        Args:
        key (str): path to file holding your key. This file should be in pem format
        passwrod (str): password for key file
        cert (str): path to certificate file. This file should be in pem format
        trustcerts (str): path to file vhere are CA certificates in.pem format
        """

        self.init_error = []
        self.key = open(key).read()
        self.password = password
        self.certificate = open(cert).read()


    def signXML(self, fiskXML, elementToSign):
        """
        signs xml template acording to XML Signature Syntax and Processing

        returns signed xml

        fiskXMLTemplate - Element (from ElementTree) xml template to sign
        elementToSign - string - name tag of element to sign inside xml template
        """

        if(self.init_error):
            raise FiskXMLEleSignerError(self.init_error)

        root = fiskXML
        #print(et.tostring(root))
        RequestElement = None

        for child in root.iter(elementToSign):
            if(child.tag == elementToSign):
                RequestElement = child
                break

        if(RequestElement == None):
            raise FiskXMLEleSignerError("Coudl not find element to sign")

        #dodavanje Signature taga
        namespace = "{http://www.w3.org/2000/09/xmldsig#}"
        Signature = et.SubElement(RequestElement, namespace + "Signature", {'Id':'placeholder'})

        #signer = xmldsig(RequestElement, digest_algorithm="sha1")
        signed_root = XMLSigner(signature_algorithm="rsa-sha1",
                                digest_algorithm="sha1",
                                c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#").sign(root,
                                    key=self.key,
                                    passphrase=self.password,
                                    cert=self.certificate,
                                    reference_uri="#" + RequestElement.get("Id"))

        return et.tostring(signed_root)

class Verifier(object):
    """
    class used for verification of reply messages

    is uses signxml module
    """
    def __init__(self, production = False):
        """
        Args:
            production (boolean): if False demo fiscalization environment will be used (default),
                if True production fiscalization environment will be used

        The locations of files holding CA cerificates are hardcoded so if you need to add some certificate
        please add it to those files.
        """
        mpath = os.path.dirname(__file__) + '/CAcerts'
        self.CAs = mpath + "/demoCAfile.pem"
        prodCAfile = mpath + "/prodCAfile.pem"
        if(production):
            self.CAs = prodCAfile

    def verifiyXML(self, xml):
        """
        verifies xml document

        Returns (ElementTree): verified xml if it can verify signature of message, or
            None if not
        """
        root = xml
        rvalue = None

        rvalue = XMLVerifier().verify(root, ca_pem_file=self.CAs, validate_schema=False)
        if(rvalue.signed_xml != None):
            rvalue = rvalue.signed_xml
        else:
            rvalue = None
        return rvalue

class FiskInitError(Exception):
    """
    exception used in FiskInit class as indicator
    of some error
    """
    def __init__(self, message):
        Exception.__init__(self, message)

class FiskInit():
    """
    class which serves as fisk.py initalizator

    mainly it should contain all info about environment and credentials
    """
    key_file = None
    password = None
    environment = None
    isset = False
    signer = None
    verifier = None

    @staticmethod
    def init(key_file, password, cert_file, production = False):
        """
        sets default fiscalization environment DEMO or PRODUCTION

        Args:
            key_file (str): path to fiscalization user key file in pem format
            password (str): password for key
            cert_file (str): path to fiscalization user certificate in pem fromat
            production (boolean): True if you need fiscalization production environment,
                for demo False. Default is False
        """
        FiskInit.key_file = key_file
        FiskInit.password = password
        FiskInit.verifier = Verifier(production)
        FiskInit.environment = FiskSOAPClientDemo()
        if (production):
            FiskInit.environment = FiskSOAPClientProduction()
        FiskInit.signer = Signer(key_file, password, cert_file)
        FiskInit.isset = True
    @staticmethod
    def deinit():
        FiskInit.key_file = None
        FiskInit.password = None
        FiskInit.environment = None
        FiskInit.signer = None
        FiskInit.verifier = None
        FiskInit.isset = False

class FiskSOAPMessage():
    """
    SOAP Envelope element

    sets SOAP elements around content
    """
    def __init__(self, content = None):
        """
        Args:
            content (ElementTree): content what will be put in SOAPMessage
        """
        namespace = "{http://schemas.xmlsoap.org/soap/envelope/}"
        self.message = et.Element(namespace + "Envelope")
        self.body = et.SubElement(self.message, namespace + "Body")
        if content != None:
            self.body.append(content.generate())

    def setBodyContent(self, content):
        """
        sets new SOAP message body content

        Args:
            content (ElementTree): content what will be put in SOAPMessage
        """
        self.body.clear()
        self.body.append(content.generate())

    def getSOAPMessage(self):
        """
        Returns (ElementTree): reprezentation of SOAPMEssage
        """
        return self.message



class FiskXMLElement(XMLElement):
    """
    base element for creating fiskla xml messages
    """
    def __init__(self, childrenNames = None, text = None, data = None, name = None):
        XMLElement.__init__(self, childrenNames, "http://www.apis-it.hr/fin/2012/types/f73", text, data, name)




class FiskXMLRequest(FiskXMLElement):
    """
    base element for creating fiskal SOAP mesage

    it knows how to send request to srever using send
    """
    def __init__(self, childrenNames = None, text = None, data = None, name = None):
        FiskXMLElement.__init__(self, childrenNames, text, data)
        self.__dict__['lastRequest'] = None
        self.__dict__['lastResponse'] = None
        self.__dict__['idPoruke'] = None
        self.__dict__['dateTime'] = None
        self.__dict__['lastError'] = None

    def getSOAPMessage(self):
        """
        adds SOAP elements to xml message
        """
        message = FiskSOAPMessage(self)
        return message.getSOAPMessage()

    def send(self):
        """
        send SOAP request to server

        """
        cl = None
        verifier = None
        signer = None
        signxmlNS = "{http://www.w3.org/2000/09/xmldsig#}"
        apisNS = "{http://www.apis-it.hr/fin/2012/types/f73}"

        if(FiskInit.isset):
            cl = FiskInit.environment
            signer = FiskInit.signer
            verifier = FiskInit.verifier
        else:
            cl = FiskSOAPClientDemo()
            #verifier = Verifier()

        self.__dict__['lastRequest'] = self.getSOAPMessage()
        #rememer generated IdPoruke nedded for return message check
        self.__dict__['idPoruke'] = None
        self.__dict__['dateTime'] = None
        try:
            self.__dict__['idPoruke'] = self.Zaglavlje.IdPoruke
            self.__dict__['dateTime'] = datetime.strptime(self.Zaglavlje.DatumVrijeme, '%d.%m.%YT%H:%M:%S')
        except NameError:
            pass

        message = et.tostring(self.__dict__['lastRequest'])

        if(signer != None and isinstance(signer, Signer)):
            message = signer.signXML(self.__dict__['lastRequest'], self.getElementName())

        reply = cl.send(message)
        has_signature = False
        verified_reply = None
        if(reply.find(".//" + signxmlNS + "Signature") != None):
            has_signature = True
        if (has_signature == True):
            if (verifier != None and isinstance(verifier, Verifier)):
                verified_reply = verifier.verifiyXML(reply)
        else:
            verified_reply = reply

        if(self.__dict__['idPoruke'] != None and verified_reply != None):
            retIdPoruke = None
            idPorukeE = verified_reply.find(".//" + apisNS + "IdPoruke")
            if(idPorukeE != None):
                retIdPoruke = idPorukeE.text
            if(self.__dict__['idPoruke'] != retIdPoruke):
                verified_reply = None
        self.__dict__['lastResponse'] = verified_reply
        return verified_reply

    def get_last_request(self):
        """
        Returns last SOAP message sent to server as ElementTree object
        """
        return self.__dict__['lastRequest']

    def get_last_response(self):
        """
        Returns last SOAP message received from server as ElementTree object
        """
        return self.__dict__['lastResponse']

    def get_last_error(self):
        """
        Returns last error which was recieved from PU serever
        """
        return self.__dict__['lastError']

    def execute(self):
        """
        This method returns reply from server or False

        If false you can check what was error with get_last_error method

        In this class this method does nothing as this is base class for other requests
        """
        self.__dict__['lastError'] = list()
        self.__dict__['lastError'].append("Class " + self.__class__.__name__ + "did not implement execute method")
        return False

    def get_id_msg(self):
        """
        returns last message id if available (Echo request does not have it)
        """
        return self.__dict__['idPoruke']

    def get_datetime_msg(self):
        """
        returns last message datetime if available (Echo request does not have it)
        """
        return self.__dict__['dateTime']



class EchoRequest(FiskXMLRequest):
    """
    EchoRequest fiskal element. This element is capable to send Echo SOAP message to server
    """
    def __init__(self, text=None):
        """
        creates Echo Request with message defined in text. Althought there is no string limit defined
        in specification I have put that text should be between 1-1000 chars
        """
        FiskXMLRequest.__init__(self, text=text, childrenNames = ( ("text", [XMLValidatorLen(1,1000), XMLValidatorRequired()]), ) )

    def execute(self):
        """
        Sends echo request to server and returns echo reply.

        If error occures returns False. You can get last error with get_last_error method
        """
        self.__dict__['lastError'] = list()
        reply = False

        self.send()
        if(isinstance(self.__dict__['lastResponse'], et._Element )):
            for relement in self.__dict__['lastResponse'].iter(self.__dict__['namespace'] + "EchoResponse"):
                reply = relement.text

            if(reply == False):
                for relement in self.__dict__['lastResponse'].iter(self.__dict__['namespace'] + "PorukaGreske"):
                    self.__dict__['lastError'].append(element.text)

        return reply


class Zaglavlje(FiskXMLElement):
    """
    Zaglavlje fiskal element

    it automaticly generates Idporuke and DateTime

    IdPoruke is regenerated on message creation so you should check this value after element generation not
        before

    Ususaly you will not use this element as it is used internaly by this library
    """
    def __init__(self):
        FiskXMLElement.__init__(self, childrenNames = ( ("IdPoruke", [XMLValidatorRegEx("^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")]),
                                              ("DatumVrijeme", [XMLValidatorRegEx("^[0-9]{2}.[0-9]{2}.[1-2][0-9]{3}T[0-9]{2}:[0-9]{2}:[0-9]{2}$")]) ) )
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
    """
    def __init__(self, data = None):
        string35Val = XMLValidatorLen(1,35)
        FiskXMLElement.__init__(self,
                                childrenNames = ( ("Ulica", [XMLValidatorLen(1,100)] ),
                                              ("KucniBroj", [XMLValidatorRegEx("^\d{1,4}$")] ),
                                              ("KucniBrojDodatak", [XMLValidatorLen(1,4)] ),
                                              ("BrojPoste", [XMLValidatorRegEx("^\d{1,12}$")] ),
                                              ("Naselje", [string35Val] ),
                                              ("Opcina", [string35Val])
                                              ),
                                data = data)


class AdresniPodatak(FiskXMLElement):
    """
    AdresniPodatak fiskal element

    can hold Addres type element or OstaliTipoviPP. this is determend in constructor
    and it is not ment to be changed later
    """
    def __init__(self, adresa):
        FiskXMLElement.__init__(self)
        if(isinstance(adresa, Adresa)):
            self.setAvailableChildren(["Adresa"])
            self.addValidator("Adresa", XMLValidatorType(Adresa))
            self.Adresa = adresa
        else:
            self.setAvailableChildren(["OstaliTipoviPP"])
            self.addValidator("OstaliTipoviPP", XMLValidatorLen(1,100))
            self.OstaliTipoviPP = adresa


class PoslovniProstor(FiskXMLElement):
    """
    PoslovniProstor element
    """
    def __init__(self, data = None):
        string1000Val = XMLValidatorLen(1,1000)
        FiskXMLElement.__init__(self, childrenNames = ( ("Oib", [XMLValidatorRegEx("^\d{11}$"), XMLValidatorRequired()]),
                                              ("OznPoslProstora", [XMLValidatorRegEx("^[0-9a-zA-Z]{1,20}$"), XMLValidatorRequired()]),
                                              ("AdresniPodatak", [XMLValidatorType(AdresniPodatak), XMLValidatorRequired()]),
                                              ("RadnoVrijeme", [string1000Val, XMLValidatorRequired()]),
                                              ("DatumPocetkaPrimjene", [XMLValidatorRegEx("^[0-9]{2}.[0-9]{2}.[1-2][0-9]{3}$"), XMLValidatorRequired()]),
                                              ("OznakaZatvaranja", [XMLValidatorEnum(["Z"])]),
                                              ("SpecNamj", [string1000Val])
                                              ),
                                data = data)


class PoslovniProstorZahtjev(FiskXMLRequest):
    """
    PoslovniProstorZahtjev element. This class is capable to sent is self as SOAP message to
    server and veifiey server seply.
    """
    def __init__(self, poslovniProstor):
        FiskXMLRequest.__init__(self, childrenNames = ( ("Zaglavlje", [XMLValidatorType(Zaglavlje)]),
                                              ("PoslovniProstor", [XMLValidatorType(PoslovniProstor), XMLValidatorRequired()])),
                                data = {"PoslovniProstor": poslovniProstor})
        self.Zaglavlje = Zaglavlje()
        self.setAttr({"Id": "ppz"})
        self.addValidator("Zaglavlje", XMLValidatorRequired())

    def execute(self):
        """
        Sends PoslovniProstorZahtjev request to server and returns True if success.

        If error occures returns False. In that case you can check error with get_last_error
        """
        self.__dict__['lastError'] = list()
        reply = False

        self.send()

        if(isinstance(self.__dict__['lastResponse'], et._Element)):
            for element in self.__dict__['lastResponse'].iter(self.__dict__['namespace'] + "PorukaGreske"):
                self.__dict__['lastError'].append(element.text)
            if(len(self.__dict__['lastError']) == 0):
                reply = True

        return reply

class BrRac(FiskXMLElement):
    """
    BrojRacuna element
    """
    def __init__(self, data = None):
        regexVal = XMLValidatorRegEx("^\d{1,20}$")
        FiskXMLElement.__init__(self, childrenNames = ( ("BrOznRac", [regexVal, XMLValidatorRequired()]),
                                              ("OznPosPr", [XMLValidatorRegEx("^[0-9a-zA-Z]{1,20}$"), XMLValidatorRequired()]),
                                              ("OznNapUr", [regexVal, XMLValidatorRequired()]) ),
                                data = data)

class Porez(FiskXMLElement):
    """
    Porez element
    """
    def __init__(self, data = None):
        regexVal = XMLValidatorRegEx("^([+-]?)[0-9]{1,15}\.[0-9]{2}$")
        FiskXMLElement.__init__(self, childrenNames = ( ("Stopa", [XMLValidatorRegEx("^([+-]?)[0-9]{1,3}\.[0-9]{2}$"), XMLValidatorRequired()]),
                                              ("Osnovica", [regexVal, XMLValidatorRequired()]),
                                              ("Iznos", [regexVal, XMLValidatorRequired()]) ),
                                data = data)

class OstPorez(FiskXMLElement):
    """
    Porez element which is cuhiled od OstaliPor elemt
    """
    def __init__(self, data = None):
        regexVal = XMLValidatorRegEx("^([+-]?)[0-9]{1,15}\.[0-9]{2}$")
        FiskXMLElement.__init__(self, childrenNames = ( ("Naziv", [XMLValidatorLen(1,100), XMLValidatorRequired()]),
                                              ("Stopa", [XMLValidatorRegEx("^([+-]?)[0-9]{1,3}\.[0-9]{2}$"), XMLValidatorRequired()]),
                                              ("Osnovica", [regexVal, XMLValidatorRequired()]),
                                              ("Iznos", [regexVal, XMLValidatorRequired()]) ),
                                data = data,
                                name = "Porez")


class Naknada(FiskXMLElement):
    """
    Naknada element
    """
    def __init__(self, data = None):
        FiskXMLElement.__init__(self, childrenNames = ( ("NazivN", [XMLValidatorLen(1,100), XMLValidatorRequired()]),
                                              ("IznosN", [XMLValidatorRegEx("^([+-]?)[0-9]{1,15}\.[0-9]{2}$"), XMLValidatorRequired()]) ),
                                data = data)


def zastitni_kod(oib, datumVrijeme, brRacuna, ozPoslovnogP, ozUredaja, ukupnoIznos, key_filename, key_password):
    """
    method which generates Zastitni kod

    it is defined as member as it is likely that you would need to call it to generate this
    code without need to create all elements for sending to server
    """
    forsigning = oib + datumVrijeme + brRacuna + ozPoslovnogP + ozUredaja + ukupnoIznos

    key = RSA.importKey(open(key_filename).read(), key_password)
    h = SHA.new(forsigning)
    signer = PKCS1_v1_5.new(key)
    signature = signer.sign(h)

    md5h = MD5.new()
    md5h.update(signature)
    return md5h.hexdigest()

class Racun(FiskXMLElement):
    """
    Racun element

    it is not possible to set ZastKod as this class calculate it each time
        you change one of varibales from it is calcualted
    """
    def __init__(self, data, key_file = None, key_password = None):
        """
        data - dict - initial data
        key_file - string - ful path of filename which holds private key needed for
            creation of ZastKod
        key_password - key password
        """
        if (key_file == None and key_password == None):
            if (not FiskInit.isset):
                raise FiskInitError("Needed members not set or fiskpy was not initalized (see FiskInit)")
            else:
                key_file = FiskInit.key_file
                key_password = FiskInit.password

        porezListVal = XMLValidatorListType(Porez)
        iznosVal = XMLValidatorRegEx("^([+-]?)[0-9]{1,15}\.[0-9]{2}$")
        oibVal = XMLValidatorRegEx("^\d{11}$")
        boolVal = XMLValidatorEnum(["true", "false"])
        FiskXMLElement.__init__(self, childrenNames = ( ("Oib", [oibVal, XMLValidatorRequired()]),
                                       ("USustPdv", [boolVal, XMLValidatorRequired()]),
                                       ("DatVrijeme", [XMLValidatorRegEx("^[0-9]{2}.[0-9]{2}.[1-2][0-9]{3}T[0-9]{2}:[0-9]{2}:[0-9]{2}$"), XMLValidatorRequired()]),
                                       ("OznSlijed", [XMLValidatorEnum(["P", "N"]), XMLValidatorRequired()]),
                                       ("BrRac", [XMLValidatorType(BrRac), XMLValidatorRequired()]),
                                       ("Pdv", [porezListVal]),
                                       ("Pnp", [porezListVal]),
                                       ("OstaliPor", [XMLValidatorListType(OstPorez)]),
                                       ("IznosOslobPdv", [iznosVal]),
                                       ("IznosMarza", [iznosVal]),
                                       ("IznosNePodlOpor", [iznosVal]),
                                       ("Naknade", [XMLValidatorListType(Naknada)]),
                                       ("IznosUkupno", [iznosVal, XMLValidatorRequired()]),
                                       ("NacinPlac", [XMLValidatorEnum(["G", "K", "C", "T", "O"]), XMLValidatorRequired()]),
                                       ("OibOper", [oibVal, XMLValidatorRequired()]),
                                       ("ZastKod", [XMLValidatorRegEx("^[a-f0-9]{32}$")]),
                                       ("NakDost", [boolVal, XMLValidatorRequired()]),
                                       ("ParagonBrRac", [XMLValidatorLen(1,100)]),
                                       ("SpecNamj", [XMLValidatorLen(1,1000)]) ),
                                data = data)
        self.__dict__["key"] = key_file
        self.__dict__["key_pass"] = key_password
        self.__dict__["items"]["ZastKod"] = zastitni_kod(self.Oib,
                                    self.DatVrijeme,
                                    self.BrRac.BrOznRac,
                                    self.BrRac.OznPosPr,
                                    self.BrRac.OznNapUr,
                                    self.IznosUkupno,
                                    self.__dict__["key"],
                                    self.__dict__["key_pass"])

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
                                            self.__dict__["key"],
                                            self.__dict__["key_pass"])

class RacunZahtjev(FiskXMLRequest):
    """
    RacunZahtijev element - has all needed to send RacunZahtijev to server
    """
    def __init__(self, racun):
        FiskXMLRequest.__init__(self, childrenNames = ( ("Zaglavlje", [XMLValidatorType(Zaglavlje)]),
                                              ("Racun", [XMLValidatorType(Racun), XMLValidatorRequired()])
                                              ),
                                data = {"Racun": racun})
        self.Zaglavlje = Zaglavlje()
        self.setAttr({"Id": "rac"})
        self.addValidator("Zaglavlje", XMLValidatorRequired())

    def execute(self):
        """
        Send RacunREquest to server. If seccessful returns JIR else False

        If returns False you can get errors with get_last_error method
        """
        self.__dict__['lastError'] = list()
        reply = False

        self.send()

        if(isinstance(self.__dict__['lastResponse'], et._Element)):
            for element in self.__dict__['lastResponse'].iter(self.__dict__['namespace'] + "Jir"):
                reply = element.text

            if(reply == False):
                for element in self.__dict__['lastResponse'].iter(self.__dict__['namespace'] + "PorukaGreske"):
                    self.__dict__['lastError'].append(element.text)

        return reply

class ProvjeraZahtjev(FiskXMLRequest):
    """
    ProvjeraZahtjev element - vorking
    """
    def __init__(self, racun):
        FiskXMLRequest.__init__(self, childrenNames = ( ("Zaglavlje", [XMLValidatorType(Zaglavlje)]),
                                              ("Racun", [XMLValidatorType(Racun), XMLValidatorRequired()])
                                              ),
                                data = {"Racun": racun})
        self.Zaglavlje = Zaglavlje()
        self.setAttr({"Id": "rac"})
        self.addValidator("Zaglavlje", XMLValidatorRequired())

    def execute(self):
        """
        Send ProvjeraZahtjec request to server.

        If returns False if request Racun data is not same as response Racun data, otherwise it returns
        Greske element from respnse so you can check them if they exists
        """
        self.__dict__['lastError'] = list()
        reply = False

        self.send()

        if(isinstance(self.__dict__['lastResponse'], et._Element)):
            for element in self.__dict__['lastResponse'].iter(self.__dict__['namespace'] + "Racun"):
                if(et.tostring(element) == et.tostring(self.Racun.generate())):
                    reply = True

            if(reply == False):
                for element in self.__dict__['lastResponse'].iter(self.__dict__['namespace'] + "Greske"):
                    reply = element

        return reply
