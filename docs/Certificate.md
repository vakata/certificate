# vakata\certificate\Certificate


## Methods

| Name | Description |
|------|-------------|
|[fromRequest](#vakata\certificate\certificatefromrequest)|Create an instance from the client request certificate.|
|[fromFile](#vakata\certificate\certificatefromfile)|Create an instance from a file.|
|[fromString](#vakata\certificate\certificatefromstring)|Create an instance from a string.|
|[__construct](#vakata\certificate\certificate__construct)|Create an instance.|
|[getData](#vakata\certificate\certificategetdata)|Get the full certificate data (as returned from x509_parse).|
|[getSubjectData](#vakata\certificate\certificategetsubjectdata)|Get the subject data from the certificate (as returned from x509_parse).|
|[getIssuerData](#vakata\certificate\certificategetissuerdata)|Get the issuer data from the certificate (as returned from x509_parse).|
|[isPersonal](#vakata\certificate\certificateispersonal)|Is the certificate personal.|
|[isProfessional](#vakata\certificate\certificateisprofessional)|Is the certificate professional.|
|[getLegalPerson](#vakata\certificate\certificategetlegalperson)|Get the legal person if available|
|[getNaturalPerson](#vakata\certificate\certificategetnaturalperson)|Get the natural person|
|[getPublicKey](#vakata\certificate\certificategetpublickey)|Get the public key from the certificate|

---



### vakata\certificate\Certificate::fromRequest
Create an instance from the client request certificate.  


```php
public static function fromRequest () : \vakata\certificate\Certificate    
```

|  | Type | Description |
|-----|-----|-----|
|  |  |  |
| `return` | [`\vakata\certificate\Certificate`](Certificate.md) | the certificate instance |

---


### vakata\certificate\Certificate::fromFile
Create an instance from a file.  


```php
public static function fromFile (  
    string $file  
) : \vakata\certificate\Certificate    
```

|  | Type | Description |
|-----|-----|-----|
| `$file` | `string` | the path to the certificate file to parse |
|  |  |  |
| `return` | [`\vakata\certificate\Certificate`](Certificate.md) | the certificate instance |

---


### vakata\certificate\Certificate::fromString
Create an instance from a string.  


```php
public static function fromString (  
    string $data  
) : \vakata\certificate\Certificate    
```

|  | Type | Description |
|-----|-----|-----|
| `$data` | `string` | the certificate |
|  |  |  |
| `return` | [`\vakata\certificate\Certificate`](Certificate.md) | the certificate instance |

---


### vakata\certificate\Certificate::__construct
Create an instance.  


```php
public function __construct (  
    string $cert  
)   
```

|  | Type | Description |
|-----|-----|-----|
| `$cert` | `string` | the certificate to parse |

---


### vakata\certificate\Certificate::getData
Get the full certificate data (as returned from x509_parse).  


```php
public function getData () : array    
```

|  | Type | Description |
|-----|-----|-----|
|  |  |  |
| `return` | `array` | the certificate data |

---


### vakata\certificate\Certificate::getSubjectData
Get the subject data from the certificate (as returned from x509_parse).  


```php
public function getSubjectData () : array    
```

|  | Type | Description |
|-----|-----|-----|
|  |  |  |
| `return` | `array` | the certificate subject data |

---


### vakata\certificate\Certificate::getIssuerData
Get the issuer data from the certificate (as returned from x509_parse).  


```php
public function getIssuerData () : array    
```

|  | Type | Description |
|-----|-----|-----|
|  |  |  |
| `return` | `array` | the certificate subject data |

---


### vakata\certificate\Certificate::isPersonal
Is the certificate personal.  


```php
public function isPersonal () : boolean    
```

|  | Type | Description |
|-----|-----|-----|
|  |  |  |
| `return` | `boolean` |  |

---


### vakata\certificate\Certificate::isProfessional
Is the certificate professional.  


```php
public function isProfessional () : boolean    
```

|  | Type | Description |
|-----|-----|-----|
|  |  |  |
| `return` | `boolean` |  |

---


### vakata\certificate\Certificate::getLegalPerson
Get the legal person if available  


```php
public function getLegalPerson () : \LegalPerson, null    
```

|  | Type | Description |
|-----|-----|-----|
|  |  |  |
| `return` | `\LegalPerson`, `null` |  |

---


### vakata\certificate\Certificate::getNaturalPerson
Get the natural person  


```php
public function getNaturalPerson () : \NaturalPerson, null    
```

|  | Type | Description |
|-----|-----|-----|
|  |  |  |
| `return` | `\NaturalPerson`, `null` |  |

---


### vakata\certificate\Certificate::getPublicKey
Get the public key from the certificate  


```php
public function getPublicKey () : string, null    
```

|  | Type | Description |
|-----|-----|-----|
|  |  |  |
| `return` | `string`, `null` |  |

---

