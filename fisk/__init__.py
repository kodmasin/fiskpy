# coding=UTF-8
"""
fisk.py - simple library for Croatian (Hrvatska) 
          fiscalization 

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

VERSION = 0.7.4
"""

from uuid import uuid4
from datetime import datetime
from xml.etree.ElementTree import Element, SubElement, tostring,\
     fromstring
import urllib2
import libxml2
import xmlsec
import re
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA, MD5
from Crypto.PublicKey import RSA
from ssl import SSLContext, PROTOCOL_SSLv23, create_default_context
import os

class XMLValidator:
    """
    base validator class
    """
    def validate(self, value):
        return True
    
class XMLValidatorLen(XMLValidator):
    """
    validator which check string lenght
    """
    def __init__(self, min_len, max_len):
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
        regex is regular expression
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
        values is list of available values
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
        typeC is object of which type value should be checked.
         Returns True if value is not set or if value is of selected
         type otherwise returns False 
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
    validator which checks are all object in list of defined type.
    Returns True if they are False if they are not. 
    """
    def __init__(self, typeC):
        """
        typeC - tpye for which list itmes will be checked
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
    cheks is value None or not. Returns True if value is not None or False
    if value is None  
    """
    def validate(self, value):
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
        
        childrenNames - tuple - ((name1, validators1), (name2, validators2), ...)
        namespace - xml namespace used for this class element and its sub elements
        text - if set and if this class does not hold any attribute that this text is text inside xml tag
        data - dict() initial data
        name - if for some reason you have to use diferent name for xml tag then class name
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
        returns xml element (ElementTree) reprezentation of this class
        
        This method also checks are all required valuesa (attributes) set
        If not it will raise ValueError exception
        """
        #generate xml as ElementTree
        xml = Element(self.__dict__["namespace"] + self.getName(), self.__dict__['attributes'])
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
    exception used in FiskXMLsec class as indicator 
    of some error
    """
    def __init__(self, message):
        Exception.__init__(self, message)

class FiskSOAPClient(object):
    """
    very very simple SOAP Client implementation
    """
    def __init__(self, host, port, url, ssl_context = None):
        """
        construct client with service arguments (host, port, url)
        
        defaults are set for DEMO envirorment
        """
        self.host = host
        self.port = port
        self.url = url
        self.context = ssl_context
    
    def send(self, message, raw = False):
        """
        send message (as xml string) to server
        
        returns ElementTree object with server response message
        
        if raw is True then returns raw xml
        """
        xml = message
        
        request = urllib2.Request(url = r"https://" + self.host + r":" + self.port + self.url, headers = {
                "Host": self.host,
                "Content-Type": "text/xml; charset=UTF-8",
                #"Content-Length": len(xml),
                "SOAPAction": self.url
            })
        rawresponse = urllib2.urlopen(url = request, data = xml, context = self.context)

        if(rawresponse.getcode() != 200):
            raise FiskSOAPClientError(str(rawresponse.getcode()) + ": " + rawresponse.info())
        response = rawresponse.read()
        if(not raw):
            response = fromstring(response)
        return response

class FiskSOAPClientDemo(FiskSOAPClient):
    """
    same class as FiskSOAPClient but with demo PU server parameters set by default 
    """
    def __init__(self):
        demoContext = create_default_context()
        mpath = os.path.dirname(__file__)
        demoContext.load_verify_locations(cafile=mpath + "/CAcerts/demoCAfile.pem")
        FiskSOAPClient.__init__(self,
                                host = r"cistest.apis-it.hr",
                                port = r"8449",
                                url = r"/FiskalizacijaServiceTest",
                                ssl_context = demoContext)
  
class FiskSOAPClientProduction(FiskSOAPClient):
    """
    same class as FiskSOAPClient but with procudtion PU server parameters set by default 
    """
    def __init__(self):
        demoContext = create_default_context()
        mpath = os.path.dirname(__file__)
        demoContext.load_verify_locations(cafile=mpath + "/CAcerts/prodCAfile.pem")
        FiskSOAPClient.__init__(self,
                                host = r"cis.porezna-uprava.hr",
                                port = r"8449",
                                url = r"/FiskalizacijaService",
                                ssl_context = demoContext)
        
class FiskXMLEleSignerError(Exception):
    """
    exception used in FiskXMLsec class as indicator 
    of some error
    """
    def __init__(self, message):
        Exception.__init__(self, message)

            
        
class FiskXMLsec(object):
    """
    class which implements signing and verifying of fiskal SOAP messages 
    
    it uses pyXMLsec library for that purpose
    """
    
    def __init__(self, key, password, cert, trustcert = None):
        """
        initize pyxmlsec lib
        
        key - string - key file path. this file should be in pem format
        passwrod - string - password for key file
        cert - string - certificate file. this file should be in pem format
        trustcert - list of strings - list of pathnames vhere are trusted (root) certificates
            for signature verification
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
                self.init_error.append("Could not load pem certificate from:" + tcert + ". If path is correct maybe it is already loaded.")
                
    
    def __del__(self):
        """
        clean up according to pyxmlsec lib
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
        if(libxml2 != None):
            libxml2.cleanupParser()
        
    
    def signTemplate(self, fiskXMLTemplate, elementToSign):
        """
        signs xml template acording to XML Signature Syntax and Processing
        
        returns signed xml
        
        fiskXMLTemplate - Element (from ElementTree) xml template to sign
        elementToSign - string - name tag of element to sign inside xml template
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
        verifies xml document
        
        returns True if it can verify signature of message, or 
            False if not
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
    
    @staticmethod
    def init(environment, key_file, password, cert_file, trustcert_files = None):
        """
        sets default fiscalization environment DEMO or PRODUCTION

        environment - should be FiskSOAPClient subclass (FiskSOAPClientDemo or FiskSOAPClientProduction)
        key_file - path to fiscalization user key file in pem format
        password - password for key
        cert_file - path to fiscalization user certificate in pem fromat
        trustcert_files - list of patsh to CA certificate files used to verify fiscalization service replys.
            Usually you can leave out this argument.
        """
        FiskInit.key_file = key_file
        FiskInit.password = password
        mpath = os.path.dirname(__file__) + '/CAcerts'
        demoCAfiles = [mpath +'/demo2012_root_ca.pem',
                       mpath +'/demo2014_root_ca.pem',
                       mpath +'/demo2014_sub_ca.pem']
        prodCAfiles = [mpath +'/RDCca.pem',
                       mpath +'/FinaRootCA.pem',
                       mpath +'/FinaRDCCA2015.pem']
        if(trustcert_files == None):
            trustcert_files = []
        if (isinstance(environment, FiskSOAPClient)):
            FiskInit.environment = environment
            if(isinstance(environment, FiskSOAPClientDemo)):
                trustcert_files = trustcert_files + demoCAfiles
            if(isinstance(environment, FiskSOAPClientProduction)):
                trustcert_files = trustcert_files + prodCAfiles
        else:
            FiskInit.environment =  FiskSOAPClientDemo()
            trustcert_files = trustcert_files + demoCAfiles
        FiskInit.signer = FiskXMLsec(key_file, password, cert_file, trustcert_files)
        FiskInit.isset = True
    @staticmethod
    def deinit():
        FiskInit.key_file = None
        FiskInit.password = None
        FiskInit.environment = None
        FiskInit.signer = None
        FiskInit.isset = False

class FiskSOAPMessage():
    """
    SOAP Envelope element
    
    sets SOAP elements around content
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
    
    def send(self, signer = None, SOAPclient = None):
        """
        send SOAP request to server
        
        singer - FiskXMLsec - element used to sign and verifiy messages
            if set to False no message will be sign or verifiey so you will
            get error from server (EchoRequest does not require signer). If set
            to None FiskInit.signer will be used if available (if fiskpy is initaized)
            
        SOAPclient - FiskSOAPClient - ususaly used to define client with different
            connection attributes (defaluts are for DEMO envirorment). If not set
            default connection parrameters will be used.
        """
        cl = SOAPclient
        if SOAPclient == None:
            if(FiskInit.isset):
                cl = FiskInit.environment
            else:
                cl = FiskSOAPClientDemo()
        if (signer == None):
            if(FiskInit.isset):
                signer = FiskInit.signer
            
        self.__dict__['lastRequest'] = self.getSOAPMessage()
        #rememer generated IdPoruke nedded for return message check
        self.__dict__['idPoruke'] = None
        self.__dict__['dateTime'] = None
        try:
            self.__dict__['idPoruke'] = self.Zaglavlje.IdPoruke
            self.__dict__['dateTime'] = datetime.strptime(self.Zaglavlje.DatumVrijeme, '%d.%m.%YT%H:%M:%S')
        except NameError:
            pass
        
        message = tostring(self.__dict__['lastRequest'])
        
        if(signer != False and isinstance(signer, FiskXMLsec)):
            message = signer.signTemplate(self.__dict__['lastRequest'], self.getElementName())
           
        reply = cl.send(message, True)
        if(signer != None and isinstance(signer, FiskXMLsec)):
            if(not signer.verifiyXML(reply)):
                reply = None
        if reply != None:
            reply = fromstring(reply)
        if(self.__dict__['idPoruke'] != None):
            retIdPoruke = None
            for element in reply.iter():
                if(element.tag.find("IdPoruke") != -1):
                    retIdPoruke = element.text
                    break
            if(self.__dict__['idPoruke'] != retIdPoruke):
                reply = None
        self.__dict__['lastResponse'] = reply
        return reply
    
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
    
    def execute(self, signer = None, SOAPclient = None):
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
        
    def execute(self, soapclient = None):
        """
        Sends echo request to server and returns echo reply.
        
        If error occures returns False. You can get last error with get_last_error method 
        """
        self.__dict__['lastError'] = list()
        reply = False
        
        self.send(False, soapclient)
        
        if(isinstance(self.__dict__['lastResponse'], Element)):
            for element in self.__dict__['lastResponse'].iter(self.__dict__['namespace'] + "EchoResponse"):
                reply = element.text
                
            if(reply == False):
                for element in self.__dict__['lastResponse'].iter(self.__dict__['namespace'] + "PorukaGreske"):
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
        
    def execute(self, signer = None, SOAPclient = None):
        """
        Sends PoslovniProstorZahtjev request to server and returns True if success.
        
        If error occures returns False. In that case you can check error with get_last_error 
        """
        self.__dict__['lastError'] = list()
        reply = False
        
        self.send(signer, SOAPclient)
        
        if(isinstance(self.__dict__['lastResponse'], Element)):
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
        
    def execute(self, signer = None, SOAPClient = None):
        """
        Send RacunREquest to server. If seccessful returns JIR else False
        
        If returns False you can get errors with get_last_error method
        """
        self.__dict__['lastError'] = list()
        reply = False
        
        self.send(signer, SOAPClient)
        
        if(isinstance(self.__dict__['lastResponse'], Element)):
            for element in self.__dict__['lastResponse'].iter(self.__dict__['namespace'] + "Jir"):
                reply = element.text
            
            if(reply == False):
                for element in self.__dict__['lastResponse'].iter(self.__dict__['namespace'] + "PorukaGreske"):
                    self.__dict__['lastError'].append(element.text)
                
        return reply

