<?php

namespace vakata\certificate;

use vakata\asn1\ASN1;
use vakata\asn1\Encoder;
use vakata\asn1\Decoder;
use vakata\asn1\structures\P7S as Parser;
use vakata\asn1\structures\TimestampResponse;

class P7S
{
    protected $p7s;
    protected $raw;

    /**
     * Create an instance from a file.
     * @param  string   $path the path to the detached signature file
     * @return P7S
     */
    public static function fromFile(string $path)
    {
        return new static(file_get_contents($path));
    }
    /**
     * Create an instance from signature data.
     * @param  string   $data the the detached signature itself
     * @return P7S
     */
    public static function fromString(string $data)
    {
        return new static($data);
    }
    /**
     * Create an instance from signature data.
     * @param  string   $data the the detached signature itself
     */
    public function __construct(string $data)
    {
        if (substr($data, 0, 10) === '-----BEGIN') {
            $data = preg_replace('(-----(BEGIN|END).*?-----)', '', $data);
            $data = str_replace(["\r", "\n"], '', $data);
            $data = base64_decode($data);
        }
        try {
            $this->p7s = Parser::fromString($data);
            $raw = Parser::map();
            $raw['children']['data']['children']['certificates']['repeat'] = [ 'tag' => ASN1::TYPE_ANY_DER ];
            $raw['children']['data']['children']['signerInfos']['repeat']['children']['signed']['tag'] = ASN1::TYPE_ANY_DER;
            $this->raw = Decoder::fromString($data)->map($raw);
        } catch (\vakata\asn1\ASN1Exception $e) {
            throw new CertificateException('Invalid signature');
        }
    }
    public function hasData(): bool
    {
        $temp = $this->p7s->toArray()['data']['content'];
        return isset($temp['data']) && $temp['type'] === '1.2.840.113549.1.7.1' && strlen($temp['data']);
    }
    public function getData(): string
    {
        return $this->hasData() ?
            Decoder::fromString($this->p7s->toArray()['data']['content']['data'])->values()[0] :
            '';
    }
    /**
     * Get all signers from the signature.
     *
     * @return array
     */
    public function getSigners() : array
    {
        $signers = [];
        foreach ($this->p7s->toArray()['data']['signerInfos'] as $k => $v) {
            $signers[$k] = [
                'hash'        => null,
                'algorithm'   => ASN1::OIDtoText($v['digest_algo']['algorithm']),
                'signed'      => null,
                'timestamp'   => null,
                'subject'     => null,
                'certificate' => null
            ];
            foreach ($v['signed'] ?? [] as $a) {
                if ($a['type'] === '1.2.840.113549.1.9.4') {
                    $signers[$k]['hash'] = strtolower(bin2hex(Decoder::fromString($a['data'][0])->values()[0]));
                }
                if ($a['type'] === '1.2.840.113549.1.9.5') {
                    $signers[$k]['signed'] = Decoder::fromString($a['data'][0])->values()[0];
                }
            }
            foreach (($v['unsigned'] ?? []) as $a) {
                if ($a['type'] === "1.2.840.113549.1.9.16.2.14") {
                    $timestamp = Decoder::fromString(
                        Decoder::fromString($a['data'][0])->values()[0][1][0][2][1][0]
                    )->map(TimestampResponse::mapToken());
                    $signers[$k]['timestamp'] = [
                        'data' => $timestamp,
                        'stamped' => $timestamp['genTime'],
                        'valid' => base64_decode($timestamp['messageImprint']['hashedMessage']) === hash(
                                ASN1::OIDtoText(
                                    $timestamp['messageImprint']['hashAlgorithm']['algorithm']
                                ),
                                base64_decode($v['signature']),
                                true
                            )
                    ];
                }
            }
            foreach ($this->p7s->toArray()['data']['certificates'] as $kk => $vv) {
                if ($v['sid']['serial'] === $vv['tbsCertificate']['serialNumber']) {
                    $cert = Certificate::fromString(
                        $this->raw['data']['certificates'][$kk]
                    );
                    $signers[$k]['subject'] = $cert->getSubjectData();
                    $signers[$k]['certificate'] = $cert->toString();
                }
            }
        }
        return $signers;
    }
    /**
     * Validate a signature against a file.
     *
     * @param string $path the path to the file
     * @return array an array of signers with their signature validation status
     */
    public function validateFile(string $path) : array
    {
        return $this->validateData(file_get_contents($path));
    }
    /**
     * Validate a signature against a hash.
     * Keep in mind this will not work on all signatures, as some signers may have different digest algorithms.
     *
     * @param string $hash the hash to validate against
     * @return array an array of signers with their signature validation status
     */
    public function validateHash(string $hash) : array
    {
        return $this->validate($hash, true);
    }
    /**
     * Validate a signature against the signed data.
     *
     * @param string $data the signed content itself
     * @return array an array of signers with their signature validation status
     */
    public function validateData(string $data = null) : array
    {
        if ($data === null && $this->hasData()) {
            $data = $this->getData();
        }
        return $this->validate($data, false);
    }
    protected function validate(string $data, bool $hashOnly = false) : array
    {
        $signers = $this->getSigners();
        foreach ($this->p7s->toArray()['data']['signerInfos'] as $k => $v) {
            $signers[$k]['valid'] = false;
            // the content hash
            $dHash = $hashOnly ? $data : strtolower(hash($signers[$k]['algorithm'], $data, false));
            // the signed hash (the same as dHash if no signed attributes are present)
            $sHash = $dHash;
            if (isset($v['signed'])) {
                $signed = $this->raw['data']['signerInfos'][$k]['signed'];
                $signed[0] = chr(17 + 32);
                $sHash = strtolower(hash($signers[$k]['algorithm'], $signed, false));
            } else {
                $signed = $hashOnly ? null : $data;
                $signers[$k]['hash'] = $dHash;
            }
            if ($signers[$k]['certificate']) {
                $signers[$k]['valid'] = $dHash === $signers[$k]['hash'] && Signature::verify(
                    $signed,
                    base64_decode($v['signature']),
                    Certificate::fromString($signers[$k]['certificate'])->getPublicKey(),
                    $signers[$k]['algorithm']
                );
            }
        }
        return $signers;
    }

    /**
     * Get all signers from a PDF file
     * @param  string   $pdf the path to the PDF file
     * @return array    all signers and their status
     */
    public static function validatePDFFile(string $path) : array
    {
        return static::validatePDF(file_get_contents($path));
    }
    /**
     * Get all signers from an XML file
     * @param  string   $path the path to the XML file
     * @return array    all signers and their status
     */
    public static function validateXMLFile(string $path, ?Certificate $crt = null) : array
    {
        return static::validateXML(file_get_contents($path), $crt);
    }
    /**
     * Get all signers from an XML file
     * @param  string   $xmlContent the XML string
     * @return array    all signers and their status
     */
    public static function validateXML(string $xmlContent, ?Certificate $crt = null) : array
    {
        $xml = new \DOMDocument();
        $xml->preserveWhiteSpace = true;
        $xml->formatOutput = false;
        $xml->loadXML($xmlContent);

        $signers = [];
        foreach ($xml->getElementsByTagName('SignedInfo') as $k => $item) {
            try {
                $alg = $item->getElementsByTagName('SignatureMethod')->item(0)->getAttribute('Algorithm');
                $alg = explode('#', $alg, 2)[1] ?? '';
                if (!isset($crt)) {
                    $crt = $item->parentNode->getElementsByTagName('X509Certificate')->item(0)->nodeValue;
                    $crt = Certificate::fromString(base64_decode($crt));
                }
                $pub = $crt->getPublicKey();
                $sig = base64_decode($item->parentNode->getElementsByTagName('SignatureValue')->item(0)->nodeValue);
                $c14 = $item->getElementsByTagName('CanonicalizationMethod')->item(0)->getAttribute('Algorithm');
                $dat1 = $item->C14N(true, strpos($c14, 'WithComments') !== false);
                $dat2 = $item->C14N(false, strpos($c14, 'WithComments') !== false);
                // assume enveloped signature
                $dlg = $item->getElementsByTagName('DigestMethod')->item(0)->getAttribute('Algorithm');
                $dlg = explode('#', $dlg, 2)[1] ?? '';
                $dig = $item->getElementsByTagName('DigestValue')->item(0)->nodeValue;
                $tmp = new \DOMDocument();
                $tmp->preserveWhiteSpace = true;
                $tmp->formatOutput = false;
                $tmp->loadXML($xmlContent);
                $sik = $tmp->getElementsByTagName('Signature')->item($k);
                $sik->parentNode->removeChild($sik);
                $ns = [];
                foreach ($item->getElementsByTagName('InclusiveNamespaces') as $in) {
                    foreach (explode(' ', $in->getAttribute('PrefixList')) as $n) {
                        $ns[] = $n;
                    }
                }
                $tmp1 = $tmp->C14N(true, strpos($c14, 'WithComments') !== false, null, $ns);
                $tmp1 = base64_encode(hash($dlg, $tmp1, true));
                $tmp2 = $tmp->C14N(false, strpos($c14, 'WithComments') !== false, null, $ns);
                $tmp2 = base64_encode(hash($dlg, $tmp2, true));
                $dig = preg_replace('(\s+)', '', $dig);
                $tmp = $dig === $tmp2 ? $tmp2 : $tmp1;
            } catch (\Throwable $e) { continue; }

            if ($crt->isEC()) {
                $map = [
                    'tag' => ASN1::TYPE_SEQUENCE,
                    'children' => [
                        'i1' => [
                            'tag' => ASN1::TYPE_INTEGER,
                            'raw' => true
                        ],
                        'i2' => [
                            'tag' => ASN1::TYPE_INTEGER,
                            'raw' => true
                        ]
                    ]
                ];
                $sig = Encoder::encode([
                    'i1' => substr($sig, 0, strlen($sig) / 2),
                    'i2' => substr($sig, strlen($sig) / 2),
                ], $map);
            }

            $signers[] = [
                'hash'        => $dig,
                'temp'        => $tmp,
                'algorithm'   => $alg,
                'signed'      => null,
                'timestamp'   => null,
                'subject'     => $crt->getSubjectData(),
                'certificate' => $crt->toString(),
                'valid'       => $dig === $tmp && 
                    (Signature::verify($dat1, $sig, $pub, $alg) || Signature::verify($dat2, $sig, $pub, $alg))
            ];
        }
        return $signers;
    }
    /**
     * Get all signers from PDF data
     * @param  string   $pdf the pdf data
     * @return array    all signers and their status
     */
    public static function validatePDF(string $pdf) : array
    {
        $signers = [];
        $matches = [];
        $current = -1;
        $append = false;
        foreach (preg_split("(\r|\n)", $pdf) as $row) {
            if (str_replace("\r", '', trim($row)) === 'endobj') {
                $append = false;
                if (isset($matches[$current]) &&
                    strpos($matches[$current], 'pkcs7.detached') === false &&
                    strpos($matches[$current], 'CAdES.detached') === false
                ) {
                    $matches[$current] = '';
                }
                continue;
            }
            if (preg_match('(^[\d ]+obj$)ui', str_replace("\r", '', trim($row)))) {
                $append = true;
                $current ++;
                $matches[$current] = '';
                continue;
            }
            if ($append) {
                $matches[$current] .= $row;
            }
        }
        foreach ($matches as $obj) {
            if (strpos($obj, 'pkcs7.detached') !== false || strpos($obj, 'CAdES.detached') !== false) {
                $ranges = explode(' ', trim(explode(']', (explode('[', $obj, 2)[1] ?? ''), 2)[0]));
                if (isset($ranges[0]) && isset($ranges[1]) && isset($ranges[2]) && isset($ranges[3])) {
                    $content = substr($pdf, $ranges[0], $ranges[1]) . substr($pdf, $ranges[2], $ranges[3]);
                    $signed = null;
                    if (preg_match("(/M\s*\(D:([\d+\-'Z]+)\))", $obj, $matches)) {
                        $signed = strtotime(str_replace("'", '', $matches[1]));
                    }
                    $signature = hex2bin(explode('>', explode('/Contents<', str_replace(["\r","\n","\t", " "], '', $obj), 2)[1], 2)[0]);
                    if ($signature) {
                        $signer = static::fromString($signature)->validateData($content);
                        foreach ($signer as $k => $s) {
                            if ($s['signed'] === null && $signed) {
                                $signer[$k]['signed'] = $signed;
                            }
                        }
                        $signers = array_merge($signers, $signer);
                    }
                } else {
                    throw new CertificateException('Invalid signature');
                }
            }
        }
        return $signers;
    }
}
