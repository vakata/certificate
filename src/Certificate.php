<?php

namespace vakata\certificate;

use vakata\asn1\Certificate as ASN1;

class Certificate
{
    protected $cert;
    protected $data;
    protected $naturalPerson;
    protected $legalPerson;

    /**
     * Create an instance from the client request certificate.
     * @return \vakata\certificate\Certificate      the certificate instance
     * @codeCoverageIgnore
     */
    public static function fromRequest() : Certificate
    {
        return new static($_SERVER['SSL_CLIENT_CERT']);
    }

    /**
     * Create an instance from a file.
     * @param  string   $file the path to the certificate file to parse
     * @return \vakata\certificate\Certificate      the certificate instance
     */
    public static function fromFile(string $file) : Certificate
    {
        return new static(file_get_contents($file));
    }

    /**
     * Create an instance from a string.
     * @param  string   $data the certificate
     * @return \vakata\certificate\Certificate      the certificate instance
     */
    public static function fromString(string $data) : Certificate
    {
        return new static($data);
    }

    /**
     * Create an instance.
     * @param  string      $cert the certificate to parse
     */
    public function __construct(string $cert)
    {
        $this->data          = $cert;
        $this->cert          = $this->parseCertificate($cert);
        $this->naturalPerson = $this->parseNaturalPerson($this->cert);
        $this->legalPerson   = $this->parseLegalPerson($this->cert);
        if ($this->naturalPerson === null) {
            list($this->naturalPerson, $this->legalPerson) = $this->parseLegacyCertificate($this->cert);
        }
        // Allowing certificates with no natural person because of infonotary certificates
        if ($this->naturalPerson === null && $this->legalPerson === null) {
            throw new CertificateException('Missing natural or legal person data');
        }
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
            $data = ASN1::parseData($cert);
            $data = $data['tbsCertificate'];
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
        return $data;
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
                    $original = $cert['extensions']['subjectAltName'][0][0] ?? [];
                    $compacted = [];
                    foreach ($original as $item) {
                        $compacted[$item[0]] = $item[1];
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
        $original = $this->cert['extensions']['subjectAltName'][0][0] ?? [];
        $compacted = [];
        foreach ($original as $item) {
            $compacted[$item[0]] = $item[1];
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
     * @return string|null
     */
    public function getPublicKey()
    {
        /*
        $temp = openssl_pkey_get_public($this->data);
        if ($temp === false) {
            return null;
        }
        $data = openssl_pkey_get_details($temp);
        return $data !== false && isset($data['key']) ? $data['key'] : null;
        */
    }
}
