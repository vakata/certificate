<?php

namespace vakata\certificate;

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
     * Parse the certificate using openssl
     *
     * @param string $cert the certificate to parse
     * @return array the parsed certificate
     */
    protected function parseCertificate(string $cert) : array
    {
        if (!is_callable('openssl_x509_parse')) {
            throw new CertificateException('OpenSSL not available');
        }
        $data = openssl_x509_parse($cert, true);
        if ($data === false || !is_array($data)) {
            throw new CertificateException('Error parsing certificate');
        }
        if (!isset($data['subject']) || !isset($data['issuer']) || !isset($data['extensions'])) {
            throw new CertificateException('Invalid certificate');
        }
        if (!isset($data['extensions']) || !isset($data['extensions']['certificatePolicies'])) {
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
                $cert['subject']['CN'],
                $temp[1],
                $temp[3],
                $temp[2],
                $cert['subject']['emailAddress'] ?? null
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
        if (!isset($legal) && isset($cert['name']) &&
            preg_match('(2\.5\.4\.97=(.*?)/)i', $cert['name'], $temp)
        ) {
            $legal = $temp[1];
        }
        if (isset($legal) &&
            preg_match('((VAT|NTR|[A-Z]{2}\:)([A-Z]{2})\-(.*))i', $legal, $temp)
        ) {
            return new LegalPerson(
                $cert['subject']['O'],
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
                if (in_array($pro, ['1.1.1.5', '1.2.1.3', '1.1.1.1', '1.2.1.2']) && isset($cert['subject']['ST'])) {
                    $parsed = $parseSubject(
                        $cert['subject'],
                        ['ST'],
                        ['EGN'=>'egn', 'PID'=>'pid', 'B'=>'bulstat']
                    );
                    if (isset($parsed['pid']) && $parsed['pid']) {
                        $nat = new NaturalPerson(
                            $cert['subject']['CN'],
                            'PNO',
                            $parsed['pid'],
                            $cert['subject']['C'] ?? null,
                            $cert['subject']['emailAddress'] ?? null
                        );
                    }
                    if (isset($parsed['egn']) && $parsed['egn']) {
                        $nat = new NaturalPerson(
                            $cert['subject']['CN'],
                            'PNO',
                            $parsed['egn'],
                            'BG',
                            $cert['subject']['emailAddress'] ?? null
                        );
                    }
                    if (in_array($pro, ['1.1.1.1', '1.2.1.2']) && isset($parsed['bulstat']) && $parsed['bulstat']) {
                        $leg = new LegalPerson(
                            $cert['subject']['O'],
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
                        ['ST', 'OU'],
                        ['EGN'=>'egn', 'PID'=>'pid', 'BULSTAT'=>'bulstat']
                    );
                    if (isset($parsed['pid']) && $parsed['pid']) {
                        $nat = new NaturalPerson(
                            $cert['subject']['CN'],
                            'PNO',
                            $parsed['pid'],
                            $cert['subject']['C'] ?? null,
                            $cert['subject']['emailAddress'] ?? null
                        );
                    }
                    if (isset($parsed['egn']) && $parsed['egn']) {
                        $nat = new NaturalPerson(
                            $cert['subject']['CN'],
                            'PNO',
                            $parsed['egn'],
                            'BG',
                            $cert['subject']['emailAddress'] ?? null
                        );
                    }
                    if (isset($parsed['bulstat']) && $parsed['bulstat']) {
                        $leg = new LegalPerson(
                            $cert['subject']['O'],
                            'NTR',
                            $parsed['bulstat'],
                            null
                        );
                    }
                }
                break;
            case 'INFONOTARY':
                if (in_array($pro, ['1.1.1.1', '1.1.1.3', '1.1.2.1', '1.1.2.3'])) {
                    if (isset($cert['extensions']['subjectAltName'])) {
                        $cntr = 'BG';
                        $temp = [];
                        if (preg_match('(countryOfCitizenship\s*=\s*([A-Z]{2})\b)i', $cert['extensions']['subjectAltName'], $temp)) {
                            $cntr = $temp[1];
                        }
                        if (preg_match('(2\.5\.4\.3\.100\.1\.1\s*=\s*(\d+)\b)i', $cert['extensions']['subjectAltName'], $temp)) {
                            $nat = new NaturalPerson(
                                $cert['subject']['CN'],
                                'PNO',
                                $temp[1],
                                $cntr,
                                $cert['subject']['emailAddress'] ?? null
                            );
                        }
                    }
                    if (in_array($pro, ['1.1.2.1', '1.1.2.3'])) {
                        $temp = [];
                        if (preg_match('(2\.5\.4\.10\.100\.1\.1\s*=\s*(\d+)\b)i', $cert['name'], $temp)) {
                            $leg = new LegalPerson(
                                $cert['subject']['O'],
                                'NTR',
                                $temp[1],
                                null
                            );
                        }
                    }
                }
                break;
            case 'SEP':
                if (in_array($pro, ['1.1.1', '2.5.1', '2.1.1', '2.5.2', '2.5.3', '2.1.2', '2.1.3']) && isset($cert['subject']['UID'])) {
                    $egn = explode('EGN', $cert['subject']['UID'], 2);
                    if (count($egn) === 2) {
                        $egn = $egn[1];
                        $nat = new NaturalPerson(
                            $cert['subject']['CN'],
                            'PNO',
                            $egn,
                            $cert['subject']['C'] ?? null,
                            $cert['subject']['emailAddress'] ?? null
                        );
                    }
                }
                if (in_array($pro, ['2.5.2', '2.5.3', '2.1.2', '2.1.3']) && isset($cert['subject']['OU'])) {
                    $ou = $cert['subject']['OU'];
                    if (is_array($ou)) {
                        $ou = implode(',', $ou);
                    }
                    $temp = [];
                    if (preg_match('(EIK(\d+))i', $ou, $temp)) {
                        $leg = new LegalPerson(
                            $cert['subject']['O'],
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
                        ['OU'],
                        ['EGNT'=>'egn', 'PID'=>'pid']
                    );
                    if (isset($parsed['pid']) && $parsed['pid']) {
                        $nat = new NaturalPerson(
                            $cert['subject']['CN'],
                            'PNO',
                            $parsed['pid'],
                            $cert['subject']['C'] ?? null,
                            $cert['subject']['emailAddress'] ?? null
                        );
                    }
                    if (isset($parsed['egn']) && $parsed['egn']) {
                        $nat = new NaturalPerson(
                            $cert['subject']['CN'],
                            'PNO',
                            $parsed['egn'],
                            'BG',
                            $cert['subject']['emailAddress'] ?? null
                        );
                    }
                } elseif (in_array($pro, ['1.1.1.3', '1.1.1.4', '1.1.1.6'])) {
                    $parsed = $parseSubject(
                        $cert['subject'],
                        ['OU', 'title'],
                        ['EGN'=>'egn', 'PID'=>'pid', 'B'=>'bulstat']
                    );
                    if (isset($parsed['pid']) && $parsed['pid']) {
                        $nat = new NaturalPerson(
                            $cert['subject']['CN'],
                            'PNO',
                            $parsed['pid'],
                            $cert['subject']['C'] ?? null,
                            $cert['subject']['emailAddress'] ?? null
                        );
                    }
                    if (isset($parsed['egn']) && $parsed['egn']) {
                        $nat = new NaturalPerson(
                            $cert['subject']['CN'],
                            'PNO',
                            $parsed['egn'],
                            'BG',
                            $cert['subject']['emailAddress'] ?? null
                        );
                    }
                    if (isset($parsed['bulstat']) && $parsed['bulstat']) {
                        $leg = new LegalPerson(
                            $cert['subject']['O'],
                            'NTR',
                            $parsed['bulstat'],
                            null
                        );
                    }
                } else {
                    $parsed = $parseSubject(
                        $cert['subject'],
                        ['OU', 'title'],
                        ['EGN' => 'egn', 'EGNT'=>'egn', 'PID'=>'pid']
                    );
                    if (isset($parsed['pid']) && $parsed['pid']) {
                        $nat = new NaturalPerson(
                            $cert['subject']['CN'],
                            'PNO',
                            $parsed['pid'],
                            $cert['subject']['C'] ?? null,
                            $cert['subject']['emailAddress'] ?? null
                        );
                    }
                    if (isset($parsed['egn']) && $parsed['egn']) {
                        $nat = new NaturalPerson(
                            $cert['subject']['CN'],
                            'PNO',
                            $parsed['egn'],
                            'BG',
                            $cert['subject']['emailAddress'] ?? null
                        );
                    }
                }
                break;
        }

        return [ $nat, $leg ];
    }

    /**
     * Get the full certificate data (as returned from x509_parse).
     * @return array  the certificate data
     */
    public function getData()
    {
        return $this->cert;
    }

    /**
     * Get the subject data from the certificate (as returned from x509_parse).
     * @return array  the certificate subject data
     */
    public function getSubjectData()
    {
        return $this->cert['subject'];
    }

    /**
     * Get the issuer data from the certificate (as returned from x509_parse).
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
        $temp = openssl_pkey_get_public($this->data);
        if ($temp === false) {
            return null;
        }
        $data = openssl_pkey_get_details($temp);
        return $data !== false && isset($data['key']) ? $data['key'] : null;
    }
}
