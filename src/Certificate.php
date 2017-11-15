<?php

namespace vakata\certificate;

use vakata\asn1\ASN1 as ASN1;
use vakata\asn1\Certificate as Parser;
use vakata\asn1\CRL as CRLParser;

class Certificate
{
    protected $cert;
    protected $data;
    protected $sign;
    protected $naturalPerson;
    protected $legalPerson;
    protected $trustedCAs = [];

    /**
     * Create an instance from the client request certificate.
     * 
     * @param  bool $requirePerson                  must the certificate contain a person (defaults to true)
     * @return \vakata\certificate\Certificate      the certificate instance
     * @codeCoverageIgnore
     */
    public static function fromRequest(bool $requirePerson = true) : Certificate
    {
        return new static($_SERVER['SSL_CLIENT_CERT'], $requirePerson);
    }

    /**
     * Create an instance from a file.
     * @param  string   $file the path to the certificate file to parse
     * @param  bool $requirePerson                  must the certificate contain a person (defaults to true)
     * @return \vakata\certificate\Certificate      the certificate instance
     */
    public static function fromFile(string $file, bool $requirePerson = true) : Certificate
    {
        return new static(file_get_contents($file), $requirePerson);
    }

    /**
     * Create an instance from a string.
     * @param  string   $data the certificate
     * @param  bool $requirePerson                  must the certificate contain a person (defaults to true)
     * @return \vakata\certificate\Certificate      the certificate instance
     */
    public static function fromString(string $data, bool $requirePerson = true) : Certificate
    {
        return new static($data, $requirePerson);
    }

    /**
     * Create an instance.
     * @param  string      $cert the certificate to parse
     * @param  bool $requirePerson                  must the certificate contain a person (defaults to true)
     */
    public function __construct(string $cert, bool $requirePerson = true)
    {
        $temp = $this->parseCertificate($cert);
        $this->data          = $cert;
        $this->cert          = $temp['cert'];
        $this->sign          = $temp['sign'];
        $this->naturalPerson = $this->parseNaturalPerson($this->cert);
        $this->legalPerson   = $this->parseLegalPerson($this->cert);
        if ($this->naturalPerson === null) {
            list($this->naturalPerson, $this->legalPerson) = $this->parseLegacyCertificate($this->cert);
        }
        // Allowing certificates with no natural person because of infonotary certificates
        if ($requirePerson && $this->naturalPerson === null && $this->legalPerson === null) {
            throw new CertificateException('Missing natural or legal person data');
        }
    }

    /**
     * Convert base256 to hex format
     *
     * @param string $inp
     * @return string
     */
    protected static function base256toHex($inp) : string
    {
        $num = ASN1::fromBase256($inp);
        $hex = '';
        for ($i = strlen($num) - 4; $i >= 0; $i-=4) {
            $hex .= dechex(bindec(substr($num, $i, 4)));
        }
        return strrev($hex);
    }

    /**
     * Validate a signature
     *
     * @param string $subject the message
     * @param string $signature the signature
     * @param string $public the public key used to sign the message
     * @param string $algorithm the algorithm used to sign the message
     * @return bool is the signature valid
     */
    protected function validateSignature($subject, $signature, $public, $algorithm) : bool
    {
        if (!is_callable('\openssl_verify')) {
            throw new CertificateException('OpenSSL not found');
        }
        if (!in_array($algorithm, openssl_get_md_methods(true))) {
            throw new CertificateException('Unsupported algorithm');
        }
        return \openssl_verify(
            $subject,
            $signature,
            $public,
            $algorithm
        ) === 1;
    }

    /**
     * Parse the certificate
     *
     * @param string $cert the certificate to parse
     * @return array the parsed certificate
     */
    protected function parseCertificate(string $cert) : array
    {
        try {
            $orig = Parser::parseData($cert);
            $data = $orig['tbsCertificate'];
        } catch (\Exception $e) {
            throw new CertificateException('Could not parse certificate');
        }
        if ($data === false || !is_array($data)) {
            throw new CertificateException('Error parsing certificate');
        }
        if (!isset($data['subject']) || !isset($data['issuer']) || !isset($data['extensions'])) {
            throw new CertificateException('Invalid certificate');
        }
        $temp = [];
        foreach ($data['subject'] as $item) {
            foreach ($item as $subitem) {
                if (isset($temp[$subitem['key']])) {
                    if (!is_array($temp[$subitem['key']])) {
                        $temp[$subitem['key']] = [ $temp[$subitem['key']] ];
                    }
                    $temp[$subitem['key']][] = $subitem['value'];
                } else {
                    $temp[$subitem['key']] = $subitem['value'];
                }
            }
        }
        $data['subject'] = $temp;
        $temp = [];
        foreach ($data['issuer'] as $item) {
            foreach ($item as $subitem) {
                if (isset($temp[$subitem['key']])) {
                    if (!is_array($temp[$subitem['key']])) {
                        $temp[$subitem['key']] = [ $temp[$subitem['key']] ];
                    }
                    $temp[$subitem['key']][] = $subitem['value'];
                } else {
                    $temp[$subitem['key']] = $subitem['value'];
                }
            }
        }
        $data['issuer'] = $temp;
        $temp = [];
        foreach ($data['extensions'] as $item) {
            $temp[$item['extnID']] = $item['extnValue'];
        }
        $data['extensions'] = $temp;
        if (!isset($data['extensions']['certificatePolicies'])) {
            throw new CertificateException('Missing certificate policies');
        }
        if (isset($data['extensions']['subjectKeyIdentifier'])) {
            $data['extensions']['subjectKeyIdentifier'] = static::base256toHex(
                $data['extensions']['subjectKeyIdentifier']
            );
        }
        if (isset($data['extensions']['authorityKeyIdentifier'])) {
            if (isset($data['extensions']['authorityKeyIdentifier'][0])) {
                $data['extensions']['authorityKeyIdentifier'][0] = static::base256toHex(
                    $data['extensions']['authorityKeyIdentifier'][0]
                );
            }
            if (isset($data['extensions']['authorityKeyIdentifier'][2])) {
                $data['extensions']['authorityKeyIdentifier'][2] = static::base256toHex(
                    $data['extensions']['authorityKeyIdentifier'][2]
                );
            }
        }
        if (strpos($cert, '-BEGIN CERTIFICATE-') !== false) {
            $cert = str_replace(['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----', "\r", "\n"], '', $cert);
            $cert = base64_decode($cert);
        }
        $temp = ASN1::decodeDER($cert, null, true);
        return [
            'cert' => $data,
            'sign' => [
                'algorithm' => $orig['signatureAlgorithm'],
                'signature' => $orig['signatureValue'],
                'subject'   => substr($cert, $temp['contents'][0]['start'], $temp['contents'][0]['length'])
            ]
        ];
    }

    /**
     * Search the certificate for data stored according to the ETSI EN 319 412-1 standard
     *
     * @param array $cert
     * @return NaturalPerson|null
     */
    protected function parseNaturalPerson(array $cert)
    {
        $natural = $cert['subject']['serialNumber'] ?? null;
        $temp = [];
        if (isset($natural) &&
            preg_match('((PAS|IDC|PNO|TAX|TIN|[A-Z]{2}\:)([A-Z]{2})\-(.*))i', $natural, $temp)
        ) {
            return new NaturalPerson(
                $cert['subject']['commonName'],
                $temp[1],
                $temp[3],
                $temp[2],
                $cert['subject']['emailAddress'] ?? null,
                $this->getSubjectData()
            );
        }
        return null;
    }

    /**
     * Search the certificate for data stored according to the ETSI EN 319 412-1 standard
     *
     * @param array $cert
     * @return LegalPerson|null
     */
    protected function parseLegalPerson(array $cert)
    {
        $legal = $cert['subject']['organizationIdentifier'] ?? null;
        if (isset($legal) &&
            preg_match('((VAT|NTR|[A-Z]{2}\:)([A-Z]{2})\-(.*))i', $legal, $temp)
        ) {
            return new LegalPerson(
                $cert['subject']['organization'],
                $temp[1],
                $temp[3],
                $temp[2]
            );
        }
        return null;
    }

    /**
     * Parse legacy certificates from Bulgarian vendors
     *
     * @param array $cert the certificate to parse
     * @return array an array of two values - the natural person and the legal person
     */
    protected function parseLegacyCertificate(array $cert)
    {
        $iss = null;
        $pro = null;
        $nat = null;
        $leg = null;
        $ext = serialize($cert['extensions']);
        foreach ([
            'STAMPIT'    => '1.3.6.1.4.1.11290',
            'BTRUST'     => '1.3.6.1.4.1.15862',
            'INFONOTARY' => '1.3.6.1.4.1.22144',
            'SEP'        => '1.3.6.1.4.1.30299',
            'SPEKTAR'    => '1.3.6.1.4.1.18463'
        ] as $issuer => $code) {
            if (preg_match('(\b('.preg_quote($code).')\.([.\d]+)\b)', $ext, $matches)) {
                $iss = $issuer;
                $pro = $matches[2];
            }
        }
        $parseSubject = function (array $data, array $fields, array $map) : array
        {
            $parsed = [];
            foreach ($fields as $field) {
                if (!isset($data[$field])) {
                    continue;
                }
                $person = $data[$field];
                if (is_array($person)) {
                    $person = implode(',', $person);
                }
                $person = array_filter(explode(',', $person));
                $temp = [];
                foreach ($person as $id) {
                    $id = explode(':', $id, 2);
                    if (count($id) === 2) {
                        foreach ($map as $k => $v) {
                            if (strtoupper($id[0]) === strtoupper($k)) {
                                $temp[strtolower($v)] = $id[1];
                            }
                        }
                    }
                }
                $parsed = array_merge($parsed, $temp);
            }
            return $parsed;
        };

        switch ($iss) {
            case 'STAMPIT':
                if (in_array($pro, ['1.1.1.5', '1.2.1.3', '1.1.1.1', '1.2.1.2']) && isset($cert['subject']['stateOrProvinceName'])) {
                    $parsed = $parseSubject(
                        $cert['subject'],
                        ['stateOrProvinceName'],
                        ['EGN'=>'egn', 'PID'=>'pid', 'B'=>'bulstat']
                    );
                    if (isset($parsed['pid']) && $parsed['pid']) {
                        $nat = new NaturalPerson(
                            $cert['subject']['commonName'],
                            'PNO',
                            $parsed['pid'],
                            $cert['subject']['countryName'] ?? null,
                            $cert['subject']['emailAddress'] ?? null,
                            $this->getSubjectData()
                        );
                    }
                    if (isset($parsed['egn']) && $parsed['egn']) {
                        $nat = new NaturalPerson(
                            $cert['subject']['commonName'],
                            'PNO',
                            $parsed['egn'],
                            'BG',
                            $cert['subject']['emailAddress'] ?? null,
                            $this->getSubjectData()
                        );
                    }
                    if (in_array($pro, ['1.1.1.1', '1.2.1.2']) && isset($parsed['bulstat']) && $parsed['bulstat']) {
                        $leg = new LegalPerson(
                            $cert['subject']['organization'],
                            'NTR',
                            $parsed['bulstat'],
                            null
                        );
                    }
                }
                break;
            case 'BTRUST':
                if ($pro === '1.5.1.1') {
                    $parsed = $parseSubject(
                        $cert['subject'],
                        ['stateOrProvinceName', 'organizationalUnit'],
                        ['EGN'=>'egn', 'PID'=>'pid', 'BULSTAT'=>'bulstat']
                    );
                    if (isset($parsed['pid']) && $parsed['pid']) {
                        $nat = new NaturalPerson(
                            $cert['subject']['commonName'],
                            'PNO',
                            $parsed['pid'],
                            $cert['subject']['countryName'] ?? null,
                            $cert['subject']['emailAddress'] ?? null,
                            $this->getSubjectData()
                        );
                    }
                    if (isset($parsed['egn']) && $parsed['egn']) {
                        $nat = new NaturalPerson(
                            $cert['subject']['commonName'],
                            'PNO',
                            $parsed['egn'],
                            'BG',
                            $cert['subject']['emailAddress'] ?? null,
                            $this->getSubjectData()
                        );
                    }
                    if (isset($parsed['bulstat']) && $parsed['bulstat']) {
                        $leg = new LegalPerson(
                            $cert['subject']['organization'],
                            'NTR',
                            $parsed['bulstat'],
                            null
                        );
                    }
                }
                break;
            case 'INFONOTARY':
                if (in_array($pro, ['1.1.1.1', '1.1.1.3', '1.1.2.1', '1.1.2.3'])) {
                    $altName = $this->cert['extensions']['subjectAltName'];
                    $original = isset($altName[0][0]) && is_array($altName[0][0]) ? $altName[0][0] : ($altName[0]??[]);
                    $compacted = [];
                    foreach ($original as $item) {
                        if (is_array($item) && count($item)) {
                            if (count($item) === 1) {
                                $item = $item[0];
                            }
                            if (count($item) > 1) {
                                $compacted[$item[0]] = $item[1];
                            }
                        }
                    }
                    if (count($compacted)) {
                        if (isset($compacted['2.5.4.3.100.1.1'])) {
                            $nat = new NaturalPerson(
                                $cert['subject']['commonName'],
                                'PNO',
                                $compacted['2.5.4.3.100.1.1'],
                                $compacted['countryOfCitizenship'] ?? 'BG',
                                $cert['subject']['emailAddress'] ?? null,
                                $this->getSubjectData()
                            );
                        }
                    }
                    if (in_array($pro, ['1.1.2.1', '1.1.2.3'])) {
                        if (isset($cert['subject']['2.5.4.10.100.1.1'])) {
                            $leg = new LegalPerson(
                                $cert['subject']['organization'],
                                'NTR',
                                $cert['subject']['2.5.4.10.100.1.1'],
                                null
                            );
                        }
                    }
                }
                break;
            case 'SEP':
                if (in_array($pro, ['1.1.1', '2.5.1', '2.1.1', '2.5.2', '2.5.3', '2.1.2', '2.1.3']) && isset($cert['subject']['userid'])) {
                    $egn = explode('EGN', $cert['subject']['userid'], 2);
                    if (count($egn) === 2) {
                        $egn = $egn[1];
                        $nat = new NaturalPerson(
                            $cert['subject']['commonName'],
                            'PNO',
                            $egn,
                            $cert['subject']['countryName'] ?? null,
                            $cert['subject']['emailAddress'] ?? null,
                            $this->getSubjectData()
                        );
                    }
                }
                if (in_array($pro, ['2.5.2', '2.5.3', '2.1.2', '2.1.3']) && isset($cert['subject']['organizationalUnit'])) {
                    $ou = $cert['subject']['organizationalUnit'];
                    if (is_array($ou)) {
                        $ou = implode(',', $ou);
                    }
                    $temp = [];
                    if (preg_match('(EIK(\d+))i', $ou, $temp)) {
                        $leg = new LegalPerson(
                            $cert['subject']['organization'],
                            'NTR',
                            $temp[1],
                            null
                        );
                    }
                }
                break;
            case 'SPEKTAR':
                if (in_array($pro, ['1.1.1.1', '1.1.1.2', '1.1.1.5'])) {
                    $parsed = $parseSubject(
                        $cert['subject'],
                        ['organizationalUnit'],
                        ['EGNT'=>'egn', 'PID'=>'pid']
                    );
                    if (isset($parsed['pid']) && $parsed['pid']) {
                        $nat = new NaturalPerson(
                            $cert['subject']['commonName'],
                            'PNO',
                            $parsed['pid'],
                            $cert['subject']['countryName'] ?? null,
                            $cert['subject']['emailAddress'] ?? null,
                            $this->getSubjectData()
                        );
                    }
                    if (isset($parsed['egn']) && $parsed['egn']) {
                        $nat = new NaturalPerson(
                            $cert['subject']['commonName'],
                            'PNO',
                            $parsed['egn'],
                            'BG',
                            $cert['subject']['emailAddress'] ?? null,
                            $this->getSubjectData()
                        );
                    }
                } elseif (in_array($pro, ['1.1.1.3', '1.1.1.4', '1.1.1.6'])) {
                    $parsed = $parseSubject(
                        $cert['subject'],
                        ['organizationalUnit', 'title'],
                        ['EGN'=>'egn', 'PID'=>'pid', 'B'=>'bulstat']
                    );
                    if (isset($parsed['pid']) && $parsed['pid']) {
                        $nat = new NaturalPerson(
                            $cert['subject']['commonName'],
                            'PNO',
                            $parsed['pid'],
                            $cert['subject']['countryName'] ?? null,
                            $cert['subject']['emailAddress'] ?? null,
                            $this->getSubjectData()
                        );
                    }
                    if (isset($parsed['egn']) && $parsed['egn']) {
                        $nat = new NaturalPerson(
                            $cert['subject']['commonName'],
                            'PNO',
                            $parsed['egn'],
                            'BG',
                            $cert['subject']['emailAddress'] ?? null,
                            $this->getSubjectData()
                        );
                    }
                    if (isset($parsed['bulstat']) && $parsed['bulstat']) {
                        $leg = new LegalPerson(
                            $cert['subject']['organization'],
                            'NTR',
                            $parsed['bulstat'],
                            null
                        );
                    }
                } else {
                    $parsed = $parseSubject(
                        $cert['subject'],
                        ['organizationalUnit', 'title'],
                        ['EGN' => 'egn', 'EGNT'=>'egn', 'PID'=>'pid']
                    );
                    if (isset($parsed['pid']) && $parsed['pid']) {
                        $nat = new NaturalPerson(
                            $cert['subject']['commonName'],
                            'PNO',
                            $parsed['pid'],
                            $cert['subject']['countryName'] ?? null,
                            $cert['subject']['emailAddress'] ?? null,
                            $this->getSubjectData()
                        );
                    }
                    if (isset($parsed['egn']) && $parsed['egn']) {
                        $nat = new NaturalPerson(
                            $cert['subject']['commonName'],
                            'PNO',
                            $parsed['egn'],
                            'BG',
                            $cert['subject']['emailAddress'] ?? null,
                            $this->getSubjectData()
                        );
                    }
                }
                break;
        }

        return [ $nat, $leg ];
    }

    /**
     * Get the full certificate data.
     * @return array  the certificate data
     */
    public function getData()
    {
        return $this->cert;
    }

    /**
     * Get the subject data from the certificate.
     * @return array  the certificate subject data
     */
    public function getSubjectData() : array
    {
        $altName = $this->cert['extensions']['subjectAltName'];
        $original = isset($altName[0][0]) && is_array($altName[0][0]) ? $altName[0][0] : ($altName[0] ?? []);
        $compacted = [];
        foreach ($original as $item) {
            if (is_array($item) && count($item)) {
                if (count($item) === 1) {
                    $item = $item[0];
                }
                if (count($item) > 1) {
                    $compacted[$item[0]] = $item[1];
                }
            }
        }
        return array_merge($compacted, $this->cert['subject']);
    }

    /**
     * Get the issuer data from the certificate.
     * @return array  the certificate subject data
     */
    public function getIssuerData()
    {
        return $this->cert['issuer'];
    }
    
    /**
     * Is the certificate personal.
     * @return boolean
     */
    public function isPersonal()
    {
        return !$this->isProfessional();
    }

    /**
     * Is the certificate professional.
     * @return boolean
     */
    public function isProfessional()
    {
        return $this->legalPerson !== null;
    }

    /**
     * Get the legal person if available
     * @return LegalPerson|null
     */
    public function getLegalPerson()
    {
        return $this->legalPerson;
    }

    /**
     * Get the natural person
     * @return NaturalPerson|null
     */
    public function getNaturalPerson()
    {
        return $this->naturalPerson;
    }

    /**
     * Get the public key from the certificate
     *
     * @param bool $pemEncoded should the result be pem encoded or raw binary, defaults to true
     * @return string
     */
    public function getPublicKey(bool $pemEncoded = true) : string
    {
        $map = [
            'tag' => ASN1::TYPE_SEQUENCE,
            'children' => [
                'algorithm' => [
                    'tag' => ASN1::TYPE_SEQUENCE,
                    'children' => [
                        "algorithm" => [
                            'tag' => ASN1::TYPE_OBJECT_IDENTIFIER
                        ],
                        'parameters' => [
                            'tag' => ASN1::TYPE_ANY,
                            'optional' => true
                        ]
                    ]
                ],
                'publicKey' => [
                    'tag' => ASN1::TYPE_BIT_STRING,
                    'raw' => true
                ]
            ]
        ];
        $pkey = ASN1::encodeDER($this->cert['SubjectPublicKeyInfo'], $map);
        if ($pemEncoded) {
            $pkey = '' .
                '-----BEGIN PUBLIC KEY-----' . "\n" .
                wordwrap(base64_encode($pkey), 64, "\n", true) . "\n" .
                '-----END PUBLIC KEY-----' . "\n";
        }
        return $pkey;
    }

    /**
     * Get the certificate's serial number in HEX form
     *
     * @return string
     */
    public function getSerialNumber() : string
    {
        return $this->getData()['serialNumber'];
    }

    /**
     * Get all certificate policy OIDs as an array of strings
     *
     * @return array
     */
    public function getPolicies() : array
    {
        $policies = [];
        $temp = $this->cert['extensions']['certificatePolicies'];
        foreach ($temp as $policy) {
            $policies[] = $policy[0];
        }
        return $policies;
    }

    /**
     * Get all certificate policy OIDs related to the CA's Certification Practice Statement as an array of strings
     *
     * @return array
     */
    public function getCPSPolicies() : array
    {
        $policies = [];
        $temp = $this->cert['extensions']['certificatePolicies'];
        foreach ($temp as $policy) {
            if (!isset($policy[1])) {
                continue;
            }
            foreach ($policy[1] as $policyId) {
                if (strtolower($policyId[0]) === 'cps') {
                    $policies[] = $policy[0];
                }
            }
        }
        return $policies;
    }

    /**
     * Add a trusted CA (used in signature validation for both certificates and CRLs)
     *
     * @param string $cert
     * @return $this
     */
    public function addTrustedCA(string $cert)
    {
        try {
            $cert = static::fromString($cert, false);
        } catch (\Exception $e) {
            throw new CertificateException('Invalid CA certificate');
        }
        if ($cert->isExpired()) {
            throw new CertificateException('Expired CA certificate');
        }
        if (!isset($cert->cert['extensions']['subjectKeyIdentifier'])) {
            throw new CertificateException('Missing CA subjectKeyIdentifier');
        }
        $this->trustedCAs[$cert->cert['extensions']['subjectKeyIdentifier']] = $cert->getPublicKey();
        return $this;
    }

    /**
     * Add trusted CA certificates (used in signature validation for both certificates and CRLs)
     *
     * @param array $certs an array of strings where each string is a CA certificate
     * @return $this
     */
    public function addTrustedCAs(array $certs)
    {
        foreach ($certs as $cert) {
            $this->addTrustedCA($cert);
        }
        return $this;
    }

    /**
     * Add trusted CAs as a bundle (used in signature validation for both certificates and CRLs)
     *
     * @param string $certs a bundle of CA certificates (the same used in Apache config)
     * @return $this
     */
    public function addTrustedCABundle(string $certs)
    {
        $certs = explode('-----END CERTIFICATE-----', $certs);
        unset($certs[count($certs) - 1]);
        return $this->addTrustedCAs($certs);
    }

    /**
     * Is the certificate valid, checks currently include dates & signature and CRL list
     *
     * @param bool $allowSelfSigned should self signed certificates be accepted (defaults to false)
     * @return bool
     */
    public function isValid(bool $allowSelfSigned = false) : bool
    {
        return !$this->isExpired() && !$this->isRevoked() && $this->isSignatureValid($allowSelfSigned);
    }

    /**
     * Is the certificate currently valid - checks notBefore and notAfter dates
     *
     * @return bool
     */
    public function isExpired() : bool
    {
        return time() < $this->cert['validity']['notBefore'] || time() > $this->cert['validity']['notAfter'];
    }

    /**
     * Is the certificate revoked - checks for CRL distrib points, downloads and parses the CRL and checks the number
     *
     * @param bool $validateSignature should the signature on the CRL be verified (defaults to true)
     * @return bool
     */
    public function isRevoked(bool $validateSignature = true) : bool
    {
        $points = $this->cert['extensions']['cRLDistributionPoints'] ?? [];
        foreach ($points as $point) {
            if (strpos($point[0], 'http') === 0) {
                $crl = @file_get_contents($point[0]);
                if ($crl === false) {
                    throw new CertificateException('Could not fetch CRL');
                }
                try {
                    $data = CRLParser::parseData($crl);
                } catch (\Exception $e) {
                    throw new CertificateException('Could not parse CRL');
                }
                if ($validateSignature) {
                    $keyID = null;
                    foreach ($data['tbsCertList']['extensions'] as $item) {
                        if ($item['extnID'] === 'authorityKeyIdentifier') {
                            if (is_array($item['extnValue'])) {
                                $item['extnValue'] = $item['extnValue'][0];
                            }
                            $keyID = static::base256toHex($item['extnValue']);
                        }
                    }
                    if (!$keyID) {
                        throw new CertificateException('CRL is missing authorityKeyIdentifier');
                    }
                    if (!isset($this->trustedCAs[$keyID])) {
                        throw new CertificateException('CA not found');
                    }
                    $temp = ASN1::decodeDER($crl, null, true);
                    if (!$this->validateSignature(
                        substr($crl, $temp['contents'][0]['start'], $temp['contents'][0]['length']),
                        substr($data['signatureValue'], 1),
                        $this->trustedCAs[$keyID],
                        $data['signatureAlgorithm']['algorithm']
                    )) {
                        throw new CertificateException('CRL has invalid signature');
                    }
                }
                foreach ($data['tbsCertList']['revokedCertificates'] as $cert) {
                    if ($cert['userCertificate'] === $this->cert['serialNumber'] &&
                        $cert['revocationDate'] <= time()
                    ) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * Check if the certificate signature is valid
     * 
     * @param bool $allowSelfSigned should self signed certificates be accepted (defaults to false)
     * @return boolean
     */
    public function isSignatureValid(bool $allowSelfSigned = false)
    {
        if ($this->cert['extensions']['authorityKeyIdentifier'][0] === $this->cert['extensions']['subjectKeyIdentifier']) {
            return $allowSelfSigned && $this->validateSignature(
                $this->sign['subject'],
                substr($this->sign['signature'], 1),
                $this->getPublicKey(),
                $this->sign['algorithm']['algorithm']
            );
        }
        if (!isset($this->trustedCAs[$this->cert['extensions']['authorityKeyIdentifier'][0]])) {
            return false;
        }
        return $this->validateSignature(
            $this->sign['subject'],
            substr($this->sign['signature'], 1),
            $this->trustedCAs[$this->cert['extensions']['authorityKeyIdentifier'][0]],
            $this->sign['algorithm']['algorithm']
        );
    }
}
