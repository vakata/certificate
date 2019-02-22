<?php

namespace vakata\certificate;

use vakata\asn1\ASN1;
use vakata\asn1\Encoder;
use vakata\asn1\Decoder;
use vakata\asn1\structures\P7S as Parser;
use vakata\asn1\structures\TimestampResponse;

class P7S
{
    /**
     * Get all signers from a file.
     * @param  string   $signature the path to the detached signature
     * @param  string   $data the path to the signed data
     * @return array    all signers
     */
    public static function fromFile(string $signature, string $data) : array
    {
        return static::fromString(file_get_contents($signature), file_get_contents($data));
    }

    /**
     * Get all signers from a data string
     * @param  string   $signature the signature
     * @param  string   $data the signed data
     * @return array    all signers
     */
    public static function fromString(string $signature, string $data) : array
    {
        $p7s  = Parser::fromString($signature);
        $raw = Parser::map();
        $raw['children']['data']['children']['certificates']['repeat'] = [ 'tag' => ASN1::TYPE_ANY_DER ];
        $raw['children']['data']['children']['signerInfos']['repeat']['children']['signed']['tag'] = ASN1::TYPE_ANY_DER;
        $raw  = Decoder::fromString($signature)->map($raw);

        $signers = [];
        foreach ($p7s->toArray()['data']['signerInfos'] as $k => $v) {
            $signers[$k] = [
                'hash'        => null,
                'algorithm'   => $v['digest_algo']['algorithm'],
                'signed'      => null,
                'valid'       => false,
                'certificate' => null,
                'timestamp'   => null
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
            foreach ($p7s->toArray()['data']['certificates'] as $kk => $vv) {
                if ($v['sid']['serial'] === $vv['tbsCertificate']['serialNumber']) {
                    $signers[$k]['certificate'] = Certificate::fromString(
                        $raw['data']['certificates'][$kk]
                    );
                }
            }
            $hash = strtolower(hash(ASN1::OIDtoText($signers[$k]['algorithm']), $data, false));
            if (isset($v['signed'])) {
                $signed = $raw['data']['signerInfos'][$k]['signed'];
                $signed[0] = chr(17 + 32);
            } else {
                $signed = $data;
                $signers[$k]['hash'] = $hash;
            }
            if ($signers[$k]['certificate']) {
                $signers[$k]['valid'] = $hash === $signers[$k]['hash'] && static::validateSignature(
                    $signed,
                    base64_decode($v['signature']),
                    $signers[$k]['certificate']->getPublicKey(),
                    $signers[$k]['algorithm']
                );
            }
        }
        return $signers;
    }

    /**
     * Get all signers from a PDF file
     * @param  string   $pdf the pdf data
     * @return array    all signers
     */
    public static function fromPDFFile(string $pdf) : array
    {
        return static::fromPDF(file_get_contents($pdf));
    }
    /**
     * Get all signers from PDF data
     * @param  string   $pdf the pdf data
     * @return array    all signers
     */
    public static function fromPDF(string $pdf) : array
    {
        $signers = [];
        if (preg_match_all('([\r\n][\d ]+obj[\r\n](.*?)endobj)i', $pdf, $matches)) {
            foreach ($matches[0] as $obj) {
                if (strpos($obj, 'pkcs7.detached') !== false) {
                    $ranges = explode(' ', trim(explode(']', explode('[', $obj, 2)[1], 2)[0]));
                    $content = substr($pdf, $ranges[0], $ranges[1]) . substr($pdf, $ranges[2], $ranges[3]);
                    $signature = hex2bin(explode('>', explode('/Contents<', $obj, 2)[1], 2)[0]);
                    $signers = array_merge($signers, static::fromString($signature, $content));
                }
            }
        }
        return $signers;
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
    protected static function validateSignature($subject, $signature, $public, $algorithm) : bool
    {
        /*
        $rslt = null;
        openssl_public_decrypt(base64_decode($info['signature']), $rslt , $public));
        Decoder::fromString($rslt)->values()[0][1]; // the hash - manual check
        */
        if (!is_callable('\openssl_verify')) {
            throw new CertificateException('OpenSSL not found');
        }
        $algorithm = ASN1::OIDtoText($algorithm);
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
}