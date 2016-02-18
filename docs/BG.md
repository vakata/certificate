# vakata\certificate\BG


## Methods

| Name | Description |
|------|-------------|
|[__construct](#vakata\certificate\bg__construct)|Create an instance.|
|[fromRequest](#vakata\certificate\bgfromrequest)|Create an instance from the client request certificate.|
|[fromFile](#vakata\certificate\bgfromfile)|Create an instance from a file.|
|[getData](#vakata\certificate\bggetdata)|Get the full certificate data (as returned from x509_parse).|
|[getSubjectData](#vakata\certificate\bggetsubjectdata)|Get the subject data from the certificate (as returned from x509_parse).|
|[getIssuerData](#vakata\certificate\bggetissuerdata)|Get the issuer data from the certificate (as returned from x509_parse).|
|[getIssuer](#vakata\certificate\bggetissuer)|Get the issuer of the certificate - one of the issuer constants.|
|[getType](#vakata\certificate\bggettype)|Get the certificate type - one of the type constants.|
|[isPersonal](#vakata\certificate\bgispersonal)|Is the certificate personal.|
|[isProfessional](#vakata\certificate\bgisprofessional)|Is the certificate professional.|
|[getBulstat](#vakata\certificate\bggetbulstat)|Get the BULSTAT number (if the certificate is a professional one)|
|[getEGN](#vakata\certificate\bggetegn)|Get the EGN - if available.|
|[getPID](#vakata\certificate\bggetpid)|Get the personal identification number - if available.|
|[getID](#vakata\certificate\bggetid)|Get the EGN or PID (whichever is available) - one will always be available in personal certificates.|
|[getSubjectName](#vakata\certificate\bggetsubjectname)|Get the name of the subject.|
|[getSubjectEmail](#vakata\certificate\bggetsubjectemail)|Get the email of the subject.|

---



### vakata\certificate\BG::__construct
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


### vakata\certificate\BG::fromRequest
Create an instance from the client request certificate.  


```php
public static function fromRequest () : \vakata\certificate\BG    
```

|  | Type | Description |
|-----|-----|-----|
|  |  |  |
| `return` | [`\vakata\certificate\BG`](BG.md) | the certificate instance |

---


### vakata\certificate\BG::fromFile
Create an instance from a file.  


```php
public static function fromFile (  
    string $file  
) : \vakata\certificate\BG    
```

|  | Type | Description |
|-----|-----|-----|
| `$file` | `string` | the path to the certificate file to parse |
|  |  |  |
| `return` | [`\vakata\certificate\BG`](BG.md) | the certificate instance |

---


### vakata\certificate\BG::getData
Get the full certificate data (as returned from x509_parse).  


```php
public function getData () : array    
```

|  | Type | Description |
|-----|-----|-----|
|  |  |  |
| `return` | `array` | the certificate data |

---


### vakata\certificate\BG::getSubjectData
Get the subject data from the certificate (as returned from x509_parse).  


```php
public function getSubjectData () : array    
```

|  | Type | Description |
|-----|-----|-----|
|  |  |  |
| `return` | `array` | the certificate subject data |

---


### vakata\certificate\BG::getIssuerData
Get the issuer data from the certificate (as returned from x509_parse).  


```php
public function getIssuerData () : array    
```

|  | Type | Description |
|-----|-----|-----|
|  |  |  |
| `return` | `array` | the certificate subject data |

---


### vakata\certificate\BG::getIssuer
Get the issuer of the certificate - one of the issuer constants.  


```php
public function getIssuer () : int    
```

|  | Type | Description |
|-----|-----|-----|
|  |  |  |
| `return` | `int` | the issuer constant |

---


### vakata\certificate\BG::getType
Get the certificate type - one of the type constants.  


```php
public function getType () : int    
```

|  | Type | Description |
|-----|-----|-----|
|  |  |  |
| `return` | `int` | the type constant |

---


### vakata\certificate\BG::isPersonal
Is the certificate personal.  


```php
public function isPersonal () : boolean    
```

|  | Type | Description |
|-----|-----|-----|
|  |  |  |
| `return` | `boolean` |  |

---


### vakata\certificate\BG::isProfessional
Is the certificate professional.  


```php
public function isProfessional () : boolean    
```

|  | Type | Description |
|-----|-----|-----|
|  |  |  |
| `return` | `boolean` |  |

---


### vakata\certificate\BG::getBulstat
Get the BULSTAT number (if the certificate is a professional one)  


```php
public function getBulstat () : string, null    
```

|  | Type | Description |
|-----|-----|-----|
|  |  |  |
| `return` | `string`, `null` | the BULSTAT number |

---


### vakata\certificate\BG::getEGN
Get the EGN - if available.  


```php
public function getEGN () : string, null    
```

|  | Type | Description |
|-----|-----|-----|
|  |  |  |
| `return` | `string`, `null` | the EGN |

---


### vakata\certificate\BG::getPID
Get the personal identification number - if available.  


```php
public function getPID () : string, null    
```

|  | Type | Description |
|-----|-----|-----|
|  |  |  |
| `return` | `string`, `null` | the PID |

---


### vakata\certificate\BG::getID
Get the EGN or PID (whichever is available) - one will always be available in personal certificates.  


```php
public function getID () : string, null    
```

|  | Type | Description |
|-----|-----|-----|
|  |  |  |
| `return` | `string`, `null` | the EGN or PID number |

---


### vakata\certificate\BG::getSubjectName
Get the name of the subject.  


```php
public function getSubjectName () : string    
```

|  | Type | Description |
|-----|-----|-----|
|  |  |  |
| `return` | `string` | the subject's name |

---


### vakata\certificate\BG::getSubjectEmail
Get the email of the subject.  


```php
public function getSubjectEmail () : string, null    
```

|  | Type | Description |
|-----|-----|-----|
|  |  |  |
| `return` | `string`, `null` | the subject's email |

---

