# X509DS - Digital Signature generation Library for XML Requests
[![Coverage Status](https://coveralls.io/repos/github/snowiow/x509ds/badge.svg?branch=master)](https://coveralls.io/github/snowiow/x509ds?branch=master)
## Introduction
X509DS is a library to help with the tedious process of appending a digital signature node to a X509 authentication request. A X509 request normally looks something like this:
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
<soapenv:Header>
  <wsa:Action xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing/" soapenv:actor="" soapenv:mustUnderstand="0">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT
  </wsa:Action>
  <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" soapenv:actor="" soapenv:mustUnderstand="1">
    <wsu:Timestamp xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="timestamp">
      <wsu:Created>2015-12-16T13:39:36Z</wsu:Created>
      <wsu:Expires>2015-12-16T13:44:36Z</wsu:Expires>
    </wsu:Timestamp>
    <wsse:BinarySecurityToken xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" wsu:Id="binarytoken">MII...</wsse:BinarySecurityToken>
  </wsse:Security>
</soapenv:Header>
<soapenv:Body xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="body">
  <RequestSecurityToken xmlns="http://schemas.xmlsoap.org/ws/2005/02/trust">
    <TokenType>http://schemas.xmlsoap.org/ws/2005/02/sc/sct</TokenType>
    <RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</RequestType>
  </RequestSecurityToken>
</soapenv:Body>
</soapenv:Envelope>
```
Most of the time you want to append a signature into the header, which hashes and canonizes some of the nodes of the XML document. Ultimatelly the whole signature node woll be signed by private key of your x509 certificate. The resulting XML document would look like this:
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
<soapenv:Header>
  <wsa:Action xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing/" soapenv:actor="" soapenv:mustUnderstand="0">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/SCT
  </wsa:Action>
  <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" soapenv:actor="" soapenv:mustUnderstand="1">
    <wsu:Timestamp xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="timestamp">
      <wsu:Created>2015-12-16T13:39:36Z</wsu:Created>
      <wsu:Expires>2015-12-16T13:44:36Z</wsu:Expires>
    </wsu:Timestamp>
    <wsse:BinarySecurityToken xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" wsu:Id="binarytoken"><MII.../wsse:BinarySecurityToken>
  </wsse:Security>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignedInfo>
            <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
            <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
            <ds:Reference URI="#body">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                <ds:DigestValue>Emk...</ds:DigestValue>
            </ds:Reference>
            <ds:Reference URI="#timestamp">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                <ds:DigestValue>2TR...</ds:DigestValue>
            </ds:Reference>
            <ds:Reference URI="#binarytoken">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                <ds:DigestValue>/Ntf...</ds:DigestValue>
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue>tuO...</ds:SignatureValue>
    </ds:Signature>
</soapenv:Header>
<soapenv:Body xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="body">
  <RequestSecurityToken xmlns="http://schemas.xmlsoap.org/ws/2005/02/trust">
    <TokenType>http://schemas.xmlsoap.org/ws/2005/02/sc/sct</TokenType>
    <RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</RequestType>
  </RequestSecurityToken>
</soapenv:Body>
</soapenv:Envelope>
```
The process of creating the signature is rather tedious, because you need to deal with the encryption and [openssl](https://secure.php.net/manual/en/openssl.installation.php) on the one hand and with the PHP []DOMDocument](https://secure.php.net/manual/en/dom.setup.php) on the other. This library is there to provide an easy interface for creating digital signatures. The corresponding PHP code for creating a digital signature like in the example before, would look like this:
```php
use X509DS\Signer;

$signer = Signer::fromPrivateKey('path/to/pkey');
$signer->setTags(
    [
        'Body'                 => '#body',
        'Timestamp'            => '#timestamp',
        'BinarySecurityToken'  => '#binarytoken',
    ]
);
$signer->setCanonization(Canonization::C14N_EXCLUSIVE);
$document = $signer->sign(self::XML); //The signed DOMDocument
$document->saveXml(); //The signed XML document as a string
```
As you can see the whole process doesn't take more than 4 statements. Of course you can configure different things on how the signature is built. More on this topic in the advanced usage part.

## Requirements
- At least PHP 7.1
- dom.so extension enabled in the php.ini ([Installation instructions](https://secure.php.net/manual/en/dom.setup.php))
- openssl.so extension enabled in the php.ini ([Installation instructions](https://secure.php.net/manual/en/openssl.installation.php))

## Installation
Via composer:  
`composer require snowiow/x509ds`

## Usage
### Create a Signer object:
Either from a private key or pfx.
#### Private Key
```php
// Either from the path of the private key
$signer = Signer::fromPrivateKey('path/to/pkey');
// or the string content of the private key
$signer = Signer::fromPrivateKey(file_get_contents('path/to/pkey'));
// or an openssl resource
$signer = Signer::fromPrivateKey(openssl_pkey_get_private(file_get_contents('path/to/pkey')));
```
#### Pfx File
```php
// Either from the path of the pfx file
$signer = Signer::fromPfx('/path/to/pfx', 'password of pfx');
// or the string content of the pfx file
$signer = Signer::fromPfx(file_get_contents('/path/to/pfx'), 'password of pfx');
```
### Set the canonization method. DEFAULT: C14N
```php
// Can be one of
$signer->setCanonization(Canonization::C14N); //Default
$signer->setCanonization(Canonization::C14N_EXCLUSIVE);
$signer->setCanonization(Canonization::C14N_WITH_COMMENTS);
$signer->setCanonization(Canonization::C14N_WITH_COMMENTS_EXCLUSIVE);
```

### Set the digest method. DEFAULT: SHA1
```php
// Can be one of
$signer->setDigestMethod(Digest::SHA1); //Default
$signer->setDigestMethod(Digest::SHA256);
$signer->setDigestMethod(Digest::SHA512);
$signer->setDigestMethod(Digest::RIPEMD160);
```
### Set the signature method. DEFAULT: SHA1
```php
// Can be one of
$signer->setSignatureMethod(Digest::SHA1); //Default
$signer->setSignatureMethod(Digest::SHA256);
$signer->setSignatureMethod(Digest::SHA512);
$signer->setSignatureMethod(Digest::RIPEMD160);
```

### Set a target. DEFAULT: Header
The signature node can be appended to an arbitrary node as a child.
```php
// Example values (namespace doesn't need to be given)
$signer->setTarget('Header'); //Default
$signer->setTarget('Body');
```
### Set the tags. DEFAULT: []
Set the names of the nodes, of which you need digest values in your signature. The method is called setTags, because the nodes will be searched via the DOMDocument method `getElementsByTagName`. Additonal methods like `getElementsByTagNameNS` and `getElementById` will be added in a later version. The tags are required as an array, where the key is the node name and the value is the uri, which will be set as an attribute in the reference node of the digest value.

```php
// Example
$signer->setTag(
    [
        'Body'                 => '#body',
        'Timestamp'            => '#timestamp',
        'BinarySecurityToken'  => '#binarytoken',
    ]
);
```

### Set a Security Token Reference Node (Optional)
Sometimes an additional SecurityTokenReference node is needed. The node will be added to the signature and looks like this:
```xml
<ds:KeyInfo>
    <wsse:SecurityTokenReference>
        <wsse:Reference URI="#binarySecurityToken">
    </wsse:SecurityTokenReference>
</ds:KeyInfo>
```
The uri can be configured:
```php
// Example
$signer->setSecurityTokenReference('#binarySecurityToken');
```

### Sign a document
Finally you can sign your XML document. This will return the modified DOMDocument with the signature node:
```php
$signedDoc = $signer->sign('path/to/xml'); // from a path
$signedDoc = $signer->sign(file_get_contents('path/to/xml')); // from a content string
// or from a DOMDocument
$document = new DOMDocument();
$document->load('path/to/xml');
$signedDoc = $signer->sign($document);
```

### Get certificate from pfx file
Because a pfx file contains both, the private key and the certificate you can also retrieve the extracted certificate and use it for example to insert it into the BinaraySecurityToken node:
```php
$signer = Signer::fromPfx('/path/to/pfx', 'password of pfx');
$cert = $signer->getCertificate();
```
