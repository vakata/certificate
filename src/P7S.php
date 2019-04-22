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
        $this->p7s = Parser::fromString($data);
        $raw = Parser::map();
        $raw['children']['data']['children']['certificates']['repeat'] = [ 'tag' => ASN1::TYPE_ANY_DER ];
        $raw['children']['data']['children']['signerInfos']['repeat']['children']['signed']['tag'] = ASN1::TYPE_ANY_DER;
        $this->raw  = Decoder::fromString($data)->map($raw);
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
            foreach ($v['unsigned'] ?? [] as $a) {
                if ($a['type'] === "1.2.840.113549.1.9.16.2.14") {
                    $signers[$k]['timestamp'] = [
                        'data' => Decoder::fromString(
                                Decoder::fromString($a['data'][0])->values()[0][1][0][2][1][0]
                            )->map(TimestampResponse::mapToken()),
                        'stamped' => $signers[$k]['timestamp']['genTime'],
                        'valid' => base64_decode($signers[$k]['timestamp']['messageImprint']['hashedMessage']) === hash(
                                ASN1::OIDtoText(
                                    $signers[$k]['timestamp']['messageImprint']['hashAlgorithm']['algorithm']
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
    public function validateData(string $data) : array
    {
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
                $temp = null;
                if (openssl_public_decrypt(
                    base64_decode($v['signature']),
                    $temp,
                    Certificate::fromString($signers[$k]['certificate'])->getPublicKey()
                )) {
                    $hash = bin2hex(Decoder::fromString($temp)->values()[0][1]);
                    $signers[$k]['valid'] = $dHash === $signers[$k]['hash'] && $sHash = $hash;
                }
                
                // $signers[$k]['valid'] = $hash === $signers[$k]['hash'] && static::validateSignature(
                //     $signed,
                //     base64_decode($v['signature']),
                //     $signers[$k]['certificate']->getPublicKey(),
                //     $signers[$k]['algorithm']
                // );

                // if (!is_callable('\openssl_verify')) {
                //     throw new CertificateException('OpenSSL not found');
                // }
                // $algorithm = ASN1::OIDtoText($algorithm);
                // if (!in_array($algorithm, openssl_get_md_methods(true))) {
                //     throw new CertificateException('Unsupported algorithm');
                // }
                // return \openssl_verify(
                //     $subject,
                //     $signature,
                //     $public,
                //     $algorithm
                // ) === 1;
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
                if (strpos($matches[$current], 'pkcs7.detached') === false) {
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
            if (strpos($obj, 'pkcs7.detached') !== false) {
                $ranges = explode(' ', trim(explode(']', explode('[', $obj, 2)[1], 2)[0]));
                $content = substr($pdf, $ranges[0], $ranges[1]) . substr($pdf, $ranges[2], $ranges[3]);
                $signature = hex2bin(explode('>', explode('/Contents<', str_replace(["\r","\n","\t", " "], '', $obj), 2)[1], 2)[0]);
                if ($signature) {
                    $signers = array_merge($signers, static::fromString($signature)->validateData($content));
                }
            }
        }
        return $signers;
    }
}