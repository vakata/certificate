<?php

namespace vakata\certificate;

// EVROTRUST
// natural: 1.3.6.1.4.1.47272.2.2
// legal: 1.3.6.1.4.1.47272.2.3

class BG
{
    /** @var Issuer StampIT */
    const STAMPIT = 1;
    /** @var Issuer B-Trust */
    const BTRUST = 2;
    /** @var Issuer Info Notary */
    const INFONOTARY = 3;
    /** @var Issuer SEP */
    const SEP = 4;
    /** @var Issuer Spektar */
    const SPEKTAR = 5;

    /** @var Type Personal */
    const PERSONAL = 6;
    /** @var Type Professional */
    const PROFESSIONAL = 7;
    /** @var Type Other */
    const OTHER = 8;
    /** @var Type Non-qualified */
    const NONQUALIFIED = 9;

    protected $cert = null;
    protected $data = null;
    protected $parsed = null;
    protected $issuer = 0;
    protected $type = 0;

    /**
     * Create an instance.
     * @param  string      $cert the certificate to parse
     */
    public function __construct($cert)
    {
        if (!is_callable('openssl_x509_parse')) {
            throw new CertificateException('OpenSSL not available');
        }
        $temp = openssl_x509_parse($cert, true);
        if ($temp === false || !is_array($temp)) {
            throw new CertificateException('Error parsing certificate');
        }
        if (!isset($temp['subject']) || !isset($temp['issuer']) || !isset($temp['extensions'])) {
            throw new CertificateException('Invalid certificate');
        }
        if (!isset($temp['extensions']) || !isset($temp['extensions']['certificatePolicies'])) {
            throw new CertificateException('Missing certificate policies');
        }
        $matches = [];
        if (!preg_match(
            '(\b(1\.3\.6\.1\.4\.1\.(?:18463|11290|15862|22144|30299))\.([.\d]+)\b)',
            serialize($temp['extensions']),
            $matches
        )) {
            throw new CertificateException('Unsupported certificate');
        }
        $issuer = $matches[1];
        $certyp = $matches[2];
        $parsed = [
            'egn' => null,
            'pid' => null,
            'bulstat' => null
        ];

        $this->type = static::OTHER;
        switch ($issuer) {
            case '1.3.6.1.4.1.11290':
                $this->issuer = static::STAMPIT;
                switch ($certyp) {
                    case '1.1.1.1':
                        // doc pro
                        $this->type = static::PROFESSIONAL;
                        break;
                    case '1.1.1.2':
                        // server
                        break;
                    case '1.1.1.3':
                        // object
                        break;
                    case '1.1.1.4':
                        // enterprise
                        $this->type = static::NONQUALIFIED;
                        break;
                    case '1.1.1.5':
                        // doc
                        $this->type = static::PERSONAL;
                        break;
                    default:
                        throw new CertificateException('Unsupported certificate type');
                }
                if (isset($temp['subject']['ST']) && $this->type !== static::OTHER) {
                    $parsed = $this->parseSubject(
                        $temp['subject'],
                        ['ST'],
                        ['EGN'=>'egn', 'PID'=>'pid', 'B'=>'bulstat']
                    );
                }
                break;
            case '1.3.6.1.4.1.15862':
                $this->issuer = static::BTRUST;
                switch ($certyp) {
                    case '1.5.1.1':
                        // personal and professional in one
                        $parsed = $this->parseSubject(
                            $temp['subject'],
                            ['ST', 'OU'],
                            ['EGN'=>'egn', 'PID'=>'pid', 'BULSTAT'=>'bulstat']
                        );
                        $this->type = isset($parsed['bulstat']) ? static::PROFESSIONAL : static::PERSONAL;
                        break;
                    default:
                        throw new CertificateException('Unsupported certificate type');
                }
                break;
            case '1.3.6.1.4.1.22144':
                $this->issuer = static::INFONOTARY;
                if (!isset($temp['extensions']['subjectAltName'])) {
                    throw new CertificateException('Unsupported certificate');
                }
                $isForeign = strpos($temp['extensions']['subjectAltName'], 'countryOfCitizenship') !== false;
                if (preg_match('(countryOfCitizenship\s*=\s*BG\b)i', $temp['extensions']['subjectAltName'])) {
                    $isForeign = false;
                }
                $egn = [];
                if (preg_match('(2\.5\.4\.3\.100\.1\.1\s*=\s*(\d+)\b)i', $temp['extensions']['subjectAltName'], $egn)) {
                    $parsed[$isForeign ? 'pid' : 'egn'] = $egn[1];
                }
                switch ($certyp) {
                    case '1.1.1.1':
                    case '1.1.1.3':
                        // personal & personal enforced CP
                        $this->type = static::PERSONAL;
                        break;
                    case '1.1.2.1':
                    case '1.1.2.3':
                        // professional & professional enforced CP
                        $this->type = static::PROFESSIONAL;
                        if (!isset($temp['name'])) {
                            throw new CertificateException('Unsupported certificate');
                        }
                        $bulstat = [];
                        if (preg_match('(2\.5\.4\.10\.100\.1\.1\s*=\s*(\d+)\b)i', $temp['name'], $bulstat)) {
                            $parsed['bulstat'] = $bulstat[1];
                        }
                        break;
                    default:
                        throw new CertificateException('Unsupported certificate type');
                }
                break;
            case '1.3.6.1.4.1.30299':
                $this->issuer = static::SEP;
                if (!isset($temp['subject']['UID'])) {
                    throw new CertificateException('Unsupported certificate');
                }
                $egn = explode('EGN', $temp['subject']['UID'], 2);
                if (count($egn) === 2) {
                    $parsed[strlen($egn[1]) === 10 ? 'egn' : 'pid'] = $egn[1];
                }
                switch ($certyp) {
                    case '1.1.1':
                        // private
                        $this->type = static::PERSONAL;
                        break;
                    case '2.5.1':
                        // private
                        $this->type = static::PERSONAL;
                        break;
                    case '2.5.2':
                        // organization
                        $this->type = static::PROFESSIONAL;
                        break;
                    case '2.5.3':
                        // profession
                        $this->type = static::PROFESSIONAL;
                        break;
                    case '2.1.1':
                        // personal
                        $this->type = static::PERSONAL;
                        break;
                    case '2.1.2':
                        // organization
                        $this->type = static::PROFESSIONAL;
                        break;
                    case '2.1.3':
                        // profession
                        $this->type = static::PROFESSIONAL;
                        break;
                    case '2.1.4':
                        // server
                        break;
                    default:
                        throw new CertificateException('Unsupported certificate type');
                }
                if ($this->type === static::PROFESSIONAL) {
                    if (isset($temp['subject']['OU'])) {
                        $ou = $temp['subject']['OU'];
                        if (is_array($ou)) {
                            $ou = implode(',', $ou);
                        }
                        $bulstat = [];
                        if (preg_match('(EIK(\d+))i', $ou, $bulstat)) {
                            $parsed['bulstat'] = $bulstat[1];
                        }
                    }
                }
                break;
            case '1.3.6.1.4.1.18463':
                $this->issuer = static::SPEKTAR;
                switch ($certyp) {
                    case '1.1.1.1':
                    case '1.1.1.2':
                    case '1.1.1.5':
                        // personal universal & personal universal restricted & qualified personal
                        $this->type = static::PERSONAL;
                        $parsed = $this->parseSubject($temp['subject'], ['OU'], ['EGNT'=>'egn', 'PID'=>'pid']);
                        break;
                    case '1.1.1.3':
                    case '1.1.1.4':
                    case '1.1.1.6':
                        // org universal & org universal restricted & qualified org
                        $this->type = static::PROFESSIONAL;
                        $parsed = $this->parseSubject(
                            $temp['subject'],
                            ['OU', 'title'],
                            ['EGN'=>'egn', 'PID'=>'pid', 'B'=>'bulstat']
                        );
                        break;
                    default:
                        throw new CertificateException('Unsupported certificate type');
                }
                break;
            default:
                throw new CertificateException('Unsupported certificate');
        }
        $this->cert = $temp;
        $this->parsed = $parsed;
    }
    /**
     * Create an instance from the client request certificate.
     * @return \vakata\certificate\BG      the certificate instance
     * @codeCoverageIgnore
     */
    public static function fromRequest()
    {
        return new static($_SERVER['SSL_CLIENT_CERT']);
    }
    /**
     * Create an instance from a file.
     * @param  string   $file the path to the certificate file to parse
     * @return \vakata\certificate\BG      the certificate instance
     */
    public static function fromFile($file)
    {
        return new static(file_get_contents($file));
    }

    protected function parseSubject($data, array $fields, array $map)
    {
        $parsed = [
            'egn' => null,
            'pid' => null,
            'bulstat' => null
        ];
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
     * Get the issuer of the certificate - one of the issuer constants.
     * @return int    the issuer constant
     */
    public function getIssuer()
    {
        return $this->issuer;
    }
    /**
     * Get the certificate type - one of the type constants.
     * @return int  the type constant
     */
    public function getType()
    {
        return $this->type;
    }
    /**
     * Is the certificate personal.
     * @return boolean
     */
    public function isPersonal()
    {
        return $this->type === static::PERSONAL;
    }
    /**
     * Is the certificate professional.
     * @return boolean
     */
    public function isProfessional()
    {
        return $this->type === static::PROFESSIONAL;
    }
    /**
     * Get the BULSTAT number (if the certificate is a professional one)
     * @return string|null   the BULSTAT number
     */
    public function getBulstat()
    {
        return $this->parsed['bulstat'];
    }
    /**
     * Get the EGN - if available.
     * @return string|null the EGN
     */
    public function getEGN()
    {
        return $this->parsed['egn'];
    }
    /**
     * Get the personal identification number - if available.
     * @return string|null the PID
     */
    public function getPID()
    {
        return $this->parsed['pid'];
    }
    /**
     * Get the EGN or PID (whichever is available) - one will always be available in personal certificates.
     * @return string|null the EGN or PID number
     */
    public function getID()
    {
        return $this->parsed['egn'] ?: $this->parsed['pid'];
    }
    /**
     * Get the name of the subject.
     * @return string the subject's name
     */
    public function getSubjectName()
    {
        return $this->cert['subject']['CN'];
    }
    /**
     * Get the email of the subject.
     * @return string|null the subject's email
     */
    public function getSubjectEmail()
    {
        return isset($this->cert['subject']['emailAddress']) ? $this->cert['subject']['emailAddress'] : null;
    }
    /**
     * Get the organization name (available if the certificate is a professional one).
     * @return string|null the subject's organization
     */
    public function getSubjectOrganization()
    {
        return isset($this->cert['subject']['O']) ? $this->cert['subject']['O'] : null;
    }
}
