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
     * @param  string   $file the path to the detached signature
     * @return \vakata\certificate\P7S      the P7S instance
     */
    public static function fromFile(string $file) : P7S
    {
        return new static(file_get_contents($file));
    }

    /**
     * Create an instance from a string.
     * @param  string   $data the detached signature
     * @return \vakata\certificate\P7S      the P7S instance
     */
    public static function fromString(string $data) : P7S
    {
        return new static($data);
    }

    /**
     * Create an instance.
     * @param  string      $cert the detached signature to parse
     */
    public function __construct(string $data)
    {
        $this->p7s  = Parser::fromString($data);
        $raw = Parser::map();
        $raw['children']['data']['children']['certificates']['repeat'] = [ 'tag' => ASN1::TYPE_ANY_DER ];
        $raw['children']['data']['children']['signerInfos']['repeat']['children']['signed']['tag'] = ASN1::TYPE_ANY_DER;
        $this->raw  = Decoder::fromString($data)->map($raw);
    }

    /**
     * Get all signers
     *
     * @param string $data the data to validate against (optional)
     * @return array
     */
    public function getSigners(string $data = null) : array
    {
        $rslt = [];
        foreach ($this->p7s->toArray()['data']['signerInfos'] as $k => $v) {
            $rslt[$k] = [
                'signed'      => null,
                'certificate' => null,
                'timestamp'   => null,
                'hash'        => null,
                'algorithm'   => $v['digest_algo']['algorithm']
            ];
            foreach ($v['signed'] ?? [] as $a) {
                if ($a['type'] === '1.2.840.113549.1.9.4') {
                    $rslt[$k]['hash'] = strtolower(bin2hex(Decoder::fromString($a['data'][0])->values()[0]));
                }
                if ($a['type'] === '1.2.840.113549.1.9.5') {
                    $rslt[$k]['signed'] = Decoder::fromString($a['data'][0])->values()[0];
                }
            }
            foreach ($v['unsigned'] ?? [] as $a) {
                if ($a['type'] === "1.2.840.113549.1.9.16.2.14") {
                    $rslt[$k]['timestamp'] = Decoder::fromString(
                        Decoder::fromString($a['data'][0])->values()[0][1][0][2][1][0]
                    )->map(TimestampResponse::mapToken());
                }
            }
            foreach ($this->p7s->toArray()['data']['certificates'] as $kk => $vv) {
                if ($v['sid']['serial'] === $vv['tbsCertificate']['serialNumber']) {
                    $rslt[$k]['certificate'] = Certificate::fromString(
                        $this->raw['data']['certificates'][$kk]
                    );
                }
            }
            if ($data !== null) {
                $rslt[$k]['signatureValid'] = false;
                $rslt[$k]['timestampValid'] = false;
                $hash = strtolower(hash(ASN1::OIDtoText($rslt[$k]['algorithm']), $data, false));
                if (isset($v['signed'])) {
                    $signed = $this->raw['data']['signerInfos'][$k]['signed'];
                    $signed[0] = chr(17 + 32);
                } else {
                    $signed = $data;
                    $rslt[$k]['hash'] = $hash;
                }
                if ($rslt[$k]['timestamp']) {
                    $rslt[$k]['timestampValid'] = base64_decode($rslt[$k]['timestamp']['messageImprint']['hashedMessage']) === hash(
                        ASN1::OIDtoText($rslt[$k]['timestamp']['messageImprint']['hashAlgorithm']['algorithm']),
                        base64_decode($v['signature']),
                        true
                    );
                }
                if ($rslt[$k]['certificate']) {
                    $rslt[$k]['signatureValid'] = $hash === $rslt[$k]['hash'] && $this->validateSignature(
                        $signed,
                        base64_decode($v['signature']),
                        $rslt[$k]['certificate']->getPublicKey(),
                        $rslt[$k]['algorithm']
                    );
                }
            }
        }
        return $rslt;
    }

    public function isValid(string $data)
    {
        foreach ($this->getSigners($data) as $signer) {
            if ($signer['timestamp'] !== null && (!isset($signer['timestampValid']) || !$signer['timestampValid'])) {
                return false;
            }
            if (!isset($signer['signatureValid']) || !$signer['signatureValid']) {
                return false;
            }
        }
        return true;
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