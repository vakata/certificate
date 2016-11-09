<?php

namespace vakata\certificate;

class BG
{
    /** @var unknown */
    const UNKNOWN       = 0;

    /** @var issuer StampIT */
    const STAMPIT       = '1.3.6.1.4.1.11290';
    /** @var issuer B-Trust */
    const BTRUST        = '1.3.6.1.4.1.15862';
    /** @var issuer Info Notary */
    const INFONOTARY    = '1.3.6.1.4.1.22144';
    /** @var issuer SEP */
    const SEP           = '1.3.6.1.4.1.30299';
    /** @var issuer Spektar */
    const SPEKTAR       = '1.3.6.1.4.1.18463';
    /** @var issuer EvroTrust */
    const EVROTRUST     = '1.3.6.1.4.1.47272';

    /** @var type Personal */
    const PERSONAL      = 1;
    /** @var type Professional */
    const PROFESSIONAL  = 2;

    protected $cert;
    protected $data;
    protected $type;
    protected $issuer;
    protected $profile;

    /**
     * Create an instance.
     * @param  string      $cert the certificate to parse
     */
    public function __construct($cert)
    {
        if (!is_callable('openssl_x509_parse')) {
            throw new CertificateException('OpenSSL not available');
        }
        $this->cert = openssl_x509_parse($cert, true);
        if ($this->cert === false || !is_array($this->cert)) {
            throw new CertificateException('Error parsing certificate');
        }
        if (!isset($this->cert['subject']) || !isset($this->cert['issuer']) || !isset($this->cert['extensions'])) {
            throw new CertificateException('Invalid certificate');
        }
        if (!isset($this->cert['extensions']) || !isset($this->cert['extensions']['certificatePolicies'])) {
            throw new CertificateException('Missing certificate policies');
        }

        $this->data     = [ 'pid' => null, 'egn' => null, 'bulstat' => null ];
        $this->type     = static::UNKNOWN;
        $this->issuer   = static::UNKNOWN;
        $this->profile  = static::UNKNOWN;

        // parse EU directive fields
        if (isset($this->cert['subject']['serialNumber'])) {
            $egn = [];
            if (preg_match('((PNOBG|IDCBG)\-(\d+))i', $this->cert['subject']['serialNumber'], $egn)) {
                $this->data[$egn[1] == 'PNOBG' ? 'egn' : 'pid'] = $egn[2];
            }
        }
        if (isset($this->cert['subject']['organizationIdentifier'])) {
            $bulstat = [];
            if (preg_match('((VARBG|NTRBG)\-(\d+))i', $this->cert['subject']['organizationIdentifier'], $bulstat)) {
                $this->data['bulstat'] = $bulstat[2];
            }
        } else if (isset($this->cert['name'])) {
            $bulstat = [];
            if (preg_match('(2\.5\.4\.97\s*=\s*(VARBG|NTRBG)\-(\d+)\b)i', $this->cert['name'], $bulstat)) {
                $this->data['bulstat'] = $bulstat[2];
            }
        }

        $ext = serialize($this->cert['extensions']);
        foreach ([
            static::STAMPIT,
            static::BTRUST,
            static::INFONOTARY,
            static::SEP,
            static::SPEKTAR,
            static::EVROTRUST
        ] as $issuer) {
            if (preg_match('(\b('.preg_quote($issuer).')\.([.\d]+)\b)', $ext, $matches)) {
                $this->issuer = $issuer;
                $this->profile = $matches[2];
                break;
            }
        }

        switch ($this->issuer) {
            case static::STAMPIT:
                if (isset($this->cert['subject']['ST'])) {
                    $this->parseSubject(
                        $this->cert['subject'],
                        ['ST'],
                        ['EGN'=>'egn', 'PID'=>'pid', 'B'=>'bulstat']
                    );
                }
                switch ($this->profile) {
                    case '1.1.1.1': // doc pro
                        $this->type = static::PROFESSIONAL;
                        break;
                    case '1.1.1.5': // doc
                        $this->type = static::PERSONAL;
                        break;
                    case '1.1.1.2': // server
                    case '1.1.1.3': // object
                    case '1.1.1.4': // enterprise
                    default:
                        break; // uknown profile
                }
                break;
            case static::BTRUST:
                $this->parseSubject(
                    $this->cert['subject'],
                    ['ST', 'OU'],
                    ['EGN'=>'egn', 'PID'=>'pid', 'BULSTAT'=>'bulstat']
                );
                switch ($this->profile) {
                    case '1.5.1.1': // personal and professional in one
                        $this->type = isset($this->data['bulstat']) ? static::PROFESSIONAL : static::PERSONAL;
                        break;
                    default: // unknown profile
                        break;
                }
                break;
            case static::INFONOTARY:
                if (isset($this->cert['extensions']['subjectAltName'])) {
                    $isForeign = strpos($this->cert['extensions']['subjectAltName'], 'countryOfCitizenship') !== false;
                    if (preg_match('(countryOfCitizenship\s*=\s*BG\b)i', $this->cert['extensions']['subjectAltName'])) {
                        $isForeign = false;
                    }
                    $egn = [];
                    if (preg_match('(2\.5\.4\.3\.100\.1\.1\s*=\s*(\d+)\b)i', $this->cert['extensions']['subjectAltName'], $egn)) {
                        $this->data[$isForeign ? 'pid' : 'egn'] = $egn[1];
                    }
                }
                switch ($this->profile) {
                    case '1.1.1.1':
                    case '1.1.1.3': // personal & personal enforced CP
                        $this->type = static::PERSONAL;
                        break;
                    case '1.1.2.1':
                    case '1.1.2.3': // professional & professional enforced CP
                        $this->type = static::PROFESSIONAL;
                        if (isset($this->cert['name'])) {
                            $bulstat = [];
                            if (preg_match('(2\.5\.4\.10\.100\.1\.1\s*=\s*(\d+)\b)i', $this->cert['name'], $bulstat)) {
                                $this->data['bulstat'] = $bulstat[1];
                            }
                        }
                        break;
                    default: // unknown
                        break;
                }
                break;
            case static::SEP:
                if (isset($this->cert['subject']['UID'])) {
                    $egn = explode('EGN', $this->cert['subject']['UID'], 2);
                    if (count($egn) === 2) {
                        $this->data[strlen($egn[1]) === 10 ? 'egn' : 'pid'] = $egn[1];
                    }
                }
                switch ($this->profile) {
                    case '1.1.1': // private
                        $this->type = static::PERSONAL;
                        break;
                    case '2.5.1': // private
                        $this->type = static::PERSONAL;
                        break;
                    case '2.5.2': // organization
                        $this->type = static::PROFESSIONAL;
                        break;
                    case '2.5.3': // profession
                        $this->type = static::PROFESSIONAL;
                        break;
                    case '2.1.1': // personal
                        $this->type = static::PERSONAL;
                        break;
                    case '2.1.2': // organization
                        $this->type = static::PROFESSIONAL;
                        break;
                    case '2.1.3': // profession
                        $this->type = static::PROFESSIONAL;
                        break;
                    case '2.1.4': // server
                    default: // unknown
                        break;
                }
                if ($this->type === static::PROFESSIONAL) {
                    if (isset($this->cert['subject']['OU'])) {
                        $ou = $this->cert['subject']['OU'];
                        if (is_array($ou)) {
                            $ou = implode(',', $ou);
                        }
                        $bulstat = [];
                        if (preg_match('(EIK(\d+))i', $ou, $bulstat)) {
                            $this->data['bulstat'] = $bulstat[1];
                        }
                    }
                }
                break;
            case static::SPEKTAR:
                switch ($this->profile) {
                    case '1.1.1.1':
                    case '1.1.1.2':
                    case '1.1.1.5': // personal universal & personal universal restricted & qualified personal
                        $this->type = static::PERSONAL;
                        $this->parseSubject($this->cert['subject'], ['OU'], ['EGNT'=>'egn', 'PID'=>'pid']);
                        break;
                    case '1.1.1.3':
                    case '1.1.1.4':
                    case '1.1.1.6': // org universal & org universal restricted & qualified org
                        $this->type = static::PROFESSIONAL;
                        $this->parseSubject(
                            $this->cert['subject'],
                            ['OU', 'title'],
                            ['EGN'=>'egn', 'PID'=>'pid', 'B'=>'bulstat']
                        );
                        break;
                    default: // uknown profile
                        $this->parseSubject($this->cert['subject'], ['OU', 'title'], ['EGN' => 'egn', 'EGNT'=>'egn', 'PID'=>'pid']);
                        break;
                }
                break;
            case static::EVROTRUST:
                switch ($this->profile) {
                    case '2.2': // personal and professional in one
                        $this->type = isset($this->data['bulstat']) ? static::PROFESSIONAL : static::PERSONAL;
                        break;
                    default: // unknown profile
                        break;
                }
                break;
            default: // unknown issuer
                break;
        }
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

    protected function parseSubject($data, array $fields, array $map, $rawName = '')
    {
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
            $this->data = array_merge($this->data, $temp);
        }
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
     * Get the issuer profile of the certificate - either a string or UNKNOWN constant.
     * @return int    the issuer constant
     */
    public function getProfile()
    {
        return $this->profile;
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
     * Is the certificate issued by a known issuer under a known profile with a known type.
     * @return boolean
     */
    public function isKnown()
    {
        return $this->type !== static::UNKNOWN && $this->type !== static::UNKNOWN && $this->profile !== static::UNKNOWN;
    }
    /**
     * Get the BULSTAT number (if the certificate is a professional one)
     * @return string|null   the BULSTAT number
     */
    public function getBulstat()
    {
        return $this->data['bulstat'];
    }
    /**
     * Get the EGN - if available.
     * @return string|null the EGN
     */
    public function getEGN()
    {
        return $this->data['egn'];
    }
    /**
     * Get the personal identification number - if available.
     * @return string|null the PID
     */
    public function getPID()
    {
        return $this->data['pid'];
    }
    /**
     * Get the EGN or PID (whichever is available) - one will always be available in personal certificates.
     * @return string|null the EGN or PID number
     */
    public function getID()
    {
        return $this->data['egn'] ?: $this->data['pid'];
    }
    /**
     * Get all IDS found in the certificate
     * @return array key value pairs of ID type => ID value
     */
    public function getIDs()
    {
        return $this->data;
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
