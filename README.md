# certificate

[![Latest Version on Packagist][ico-version]][link-packagist]
[![Software License][ico-license]](LICENSE.md)
[![Build Status][ico-travis]][link-travis]
[![Code Climate][ico-cc]][link-cc]
[![Tests Coverage][ico-cc-coverage]][link-cc]

Parsing of digital certificates from all Bulgarian vendors (and all other vendors compatible with [the common EU standard](http://www.etsi.org/deliver/etsi_en/319400_319499/31941201/01.01.00_30/en_31941201v010100v.pdf)).

## Install

Via Composer

``` bash
$ composer require vakata/certificate
```

## Usage

``` php
// parse the certificate from the current request ($_SERVER['SSL_CLIENT_CERT'])
// on Apache this will work if SSLOptions +ExportCertData is set
$cert = \vakata\certificate\Certificate::fromRequest();

// you can then get various information from the certificate
echo $cert->getNaturalPerson()->getID(); // EGN or PID
if ($cert->isProfessional()) {
    echo $cert->getLegalPerson()->getBulstat(); // BULSTAT
}

// you can also create an instance from a x509 string
$certStr = new \vakata\certificate\Certificate("x509 formatted string");
// or using a static method
$certStr = new \vakata\certificate\Certificate::fromString("x509 formatted string");
// or from a file
$certFile = \vakata\certificate\Certificate::fromFile("/path/to/file.crt");
```

Certificates can also be validated (by checking expiration dates, CRLs and validating the certificate signature). Keep in mind signature verification is implemented using the OpenSSL PHP extension.

Read more in the [API docs](docs/README.md)

## Testing

``` bash
$ composer test
```


## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

## Security

If you discover any security related issues, please email github@vakata.com instead of using the issue tracker.

## Credits

- [vakata][link-author]
- [All Contributors][link-contributors]

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information. 

[ico-version]: https://img.shields.io/packagist/v/vakata/certificate.svg?style=flat-square
[ico-license]: https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square
[ico-travis]: https://img.shields.io/travis/vakata/certificate/master.svg?style=flat-square
[ico-scrutinizer]: https://img.shields.io/scrutinizer/coverage/g/vakata/certificate.svg?style=flat-square
[ico-code-quality]: https://img.shields.io/scrutinizer/g/vakata/certificate.svg?style=flat-square
[ico-downloads]: https://img.shields.io/packagist/dt/vakata/certificate.svg?style=flat-square
[ico-cc]: https://img.shields.io/codeclimate/github/vakata/certificate.svg?style=flat-square
[ico-cc-coverage]: https://img.shields.io/codeclimate/coverage/github/vakata/certificate.svg?style=flat-square

[link-packagist]: https://packagist.org/packages/vakata/certificate
[link-travis]: https://travis-ci.org/vakata/certificate
[link-scrutinizer]: https://scrutinizer-ci.com/g/vakata/certificate/code-structure
[link-code-quality]: https://scrutinizer-ci.com/g/vakata/certificate
[link-downloads]: https://packagist.org/packages/vakata/certificate
[link-author]: https://github.com/vakata
[link-contributors]: ../../contributors
[link-cc]: https://codeclimate.com/github/vakata/certificate

