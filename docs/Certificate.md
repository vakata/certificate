# vakata\certificate\Certificate  







## Methods

| Name | Description |
|------|-------------|
|[__construct](#certificate__construct)|Create an instance.|
|[addTrustedCA](#certificateaddtrustedca)|Add a trusted CA (used in signature validation for both certificates and CRLs)|
|[addTrustedCABundle](#certificateaddtrustedcabundle)|Add trusted CAs as a bundle (used in signature validation for both certificates and CRLs)|
|[addTrustedCAs](#certificateaddtrustedcas)|Add trusted CA certificates (used in signature validation for both certificates and CRLs)|
|[fromFile](#certificatefromfile)|Create an instance from a file.|
|[fromRequest](#certificatefromrequest)|Create an instance from the client request certificate.|
|[fromString](#certificatefromstring)|Create an instance from a string.|
|[getCPSPolicies](#certificategetcpspolicies)|Get all certificate policy OIDs related to the CA's Certification Practice Statement as an array of strings|
|[getData](#certificategetdata)|Get the full certificate data.|
|[getIssuerData](#certificategetissuerdata)|Get the issuer data from the certificate.|
|[getLegalPerson](#certificategetlegalperson)|Get the legal person if available|
|[getNaturalPerson](#certificategetnaturalperson)|Get the natural person|
|[getPolicies](#certificategetpolicies)|Get all certificate policy OIDs as an array of strings|
|[getPublicKey](#certificategetpublickey)|Get the public key from the certificate|
|[getSerialNumber](#certificategetserialnumber)|Get the certificate's serial number in HEX form|
|[getSubjectData](#certificategetsubjectdata)|Get the subject data from the certificate.|
|[isExpired](#certificateisexpired)|Is the certificate currently valid - checks notBefore and notAfter dates|
|[isPersonal](#certificateispersonal)|Is the certificate personal.|
|[isProfessional](#certificateisprofessional)|Is the certificate professional.|
|[isRevoked](#certificateisrevoked)|Is the certificate revoked - checks for CRL distrib points, downloads and parses the CRL and checks the number|
|[isSignatureValid](#certificateissignaturevalid)|Check if the certificate signature is valid|
|[isValid](#certificateisvalid)|Is the certificate valid, checks currently include dates & signature and CRL list|




### Certificate::__construct  

**Description**

```php
public __construct (string $cert, bool $requirePerson)
```

Create an instance. 

 

**Parameters**

* `(string) $cert`
: the certificate to parse  
* `(bool) $requirePerson`
: must the certificate contain a person (defaults to true)  

**Return Values**




### Certificate::addTrustedCA  

**Description**

```php
public addTrustedCA (string $cert)
```

Add a trusted CA (used in signature validation for both certificates and CRLs) 

 

**Parameters**

* `(string) $cert`

**Return Values**

`$this`





### Certificate::addTrustedCABundle  

**Description**

```php
public addTrustedCABundle (string $certs)
```

Add trusted CAs as a bundle (used in signature validation for both certificates and CRLs) 

 

**Parameters**

* `(string) $certs`
: a bundle of CA certificates (the same used in Apache config)  

**Return Values**

`$this`





### Certificate::addTrustedCAs  

**Description**

```php
public addTrustedCAs (array $certs)
```

Add trusted CA certificates (used in signature validation for both certificates and CRLs) 

 

**Parameters**

* `(array) $certs`
: an array of strings where each string is a CA certificate  

**Return Values**

`$this`





### Certificate::fromFile  

**Description**

```php
public static fromFile (string $file, bool $requirePerson)
```

Create an instance from a file. 

 

**Parameters**

* `(string) $file`
: the path to the certificate file to parse  
* `(bool) $requirePerson`
: must the certificate contain a person (defaults to true)  

**Return Values**

`\vakata\certificate\Certificate`

> the certificate instance  




### Certificate::fromRequest  

**Description**

```php
public static fromRequest (bool $requirePerson)
```

Create an instance from the client request certificate. 

 

**Parameters**

* `(bool) $requirePerson`
: must the certificate contain a person (defaults to true)  

**Return Values**

`\vakata\certificate\Certificate`

> the certificate instance  




### Certificate::fromString  

**Description**

```php
public static fromString (string $data, bool $requirePerson)
```

Create an instance from a string. 

 

**Parameters**

* `(string) $data`
: the certificate  
* `(bool) $requirePerson`
: must the certificate contain a person (defaults to true)  

**Return Values**

`\vakata\certificate\Certificate`

> the certificate instance  




### Certificate::getCPSPolicies  

**Description**

```php
public getCPSPolicies (void)
```

Get all certificate policy OIDs related to the CA's Certification Practice Statement as an array of strings 

 

**Parameters**

`This function has no parameters.`

**Return Values**

`array`





### Certificate::getData  

**Description**

```php
public getData (void)
```

Get the full certificate data. 

 

**Parameters**

`This function has no parameters.`

**Return Values**

`array`

> the certificate data  




### Certificate::getIssuerData  

**Description**

```php
public getIssuerData (void)
```

Get the issuer data from the certificate. 

 

**Parameters**

`This function has no parameters.`

**Return Values**

`array`

> the certificate subject data  




### Certificate::getLegalPerson  

**Description**

```php
public getLegalPerson (void)
```

Get the legal person if available 

 

**Parameters**

`This function has no parameters.`

**Return Values**

`\LegalPerson|null`





### Certificate::getNaturalPerson  

**Description**

```php
public getNaturalPerson (void)
```

Get the natural person 

 

**Parameters**

`This function has no parameters.`

**Return Values**

`\NaturalPerson|null`





### Certificate::getPolicies  

**Description**

```php
public getPolicies (void)
```

Get all certificate policy OIDs as an array of strings 

 

**Parameters**

`This function has no parameters.`

**Return Values**

`array`





### Certificate::getPublicKey  

**Description**

```php
public getPublicKey (bool $pemEncoded)
```

Get the public key from the certificate 

 

**Parameters**

* `(bool) $pemEncoded`
: should the result be pem encoded or raw binary, defaults to true  

**Return Values**

`string`





### Certificate::getSerialNumber  

**Description**

```php
public getSerialNumber (void)
```

Get the certificate's serial number in HEX form 

 

**Parameters**

`This function has no parameters.`

**Return Values**

`string`





### Certificate::getSubjectData  

**Description**

```php
public getSubjectData (void)
```

Get the subject data from the certificate. 

 

**Parameters**

`This function has no parameters.`

**Return Values**

`array`

> the certificate subject data  




### Certificate::isExpired  

**Description**

```php
public isExpired (void)
```

Is the certificate currently valid - checks notBefore and notAfter dates 

 

**Parameters**

`This function has no parameters.`

**Return Values**

`bool`





### Certificate::isPersonal  

**Description**

```php
public isPersonal (void)
```

Is the certificate personal. 

 

**Parameters**

`This function has no parameters.`

**Return Values**

`boolean`





### Certificate::isProfessional  

**Description**

```php
public isProfessional (void)
```

Is the certificate professional. 

 

**Parameters**

`This function has no parameters.`

**Return Values**

`boolean`





### Certificate::isRevoked  

**Description**

```php
public isRevoked (bool $validateSignature)
```

Is the certificate revoked - checks for CRL distrib points, downloads and parses the CRL and checks the number 

 

**Parameters**

* `(bool) $validateSignature`
: should the signature on the CRL be verified (defaults to true)  

**Return Values**

`bool`





### Certificate::isSignatureValid  

**Description**

```php
public isSignatureValid (bool $allowSelfSigned)
```

Check if the certificate signature is valid 

 

**Parameters**

* `(bool) $allowSelfSigned`
: should self signed certificates be accepted (defaults to false)  

**Return Values**

`boolean`





### Certificate::isValid  

**Description**

```php
public isValid (bool $allowSelfSigned)
```

Is the certificate valid, checks currently include dates & signature and CRL list 

 

**Parameters**

* `(bool) $allowSelfSigned`
: should self signed certificates be accepted (defaults to false)  

**Return Values**

`bool`




