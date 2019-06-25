<?php

namespace vakata\certificate;

use vakata\asn1\ASN1;
use vakata\asn1\Decoder;
use vakata\asn1\structures\CRL as Parser;

class CRL
{
    protected $data;

    protected static function base256toHex($inp) : string
    {
        $num = ASN1::fromBase256($inp);
        $hex = '';
        for ($i = strlen($num) - 4; $i >= 0; $i-=4) {
            $hex .= dechex(bindec(substr($num, $i, 4)));
        }
        return strrev($hex);
    }

    public function __construct(Parser $data)
    {
        $this->data = $data;
    }
    public static function fromString(string $data) : CRL
    {
        return new static(Parser::fromString($data));
    }
    public static function fromFile(string $path) : CRL
    {
        return new static(Parser::fromFile($path));
    }
    public function getAuthorityKeyIdentifier()
    {
        $temp = $this->data->toArray(false, true)['tbsCertList']['extensions'];
        if (!$temp) {
            return null;
        }
        foreach ($temp as $item) {
            if ($item['extnID'] === ASN1::TextToOID('authorityKeyIdentifier')) {
                $val = $item['extnValue'];
                while (!is_string($val) && isset($val[0])) {
                    $val = $val[0];
                }
                if (is_string($val)) {
                    return static::base256toHex($val);
                }
            }
        }
        return null;
    }
    public function isSignatureValid(array $ca) : bool
    {
        $keyID = $this->getAuthorityKeyIdentifier();
        $found = null;
        if ($keyID === null) {
            $found = array_values($ca)[0] ?? null;
        } else {
            foreach ($ca as $cert) {
                if ($cert->getSubjectKeyIdentifier() === $keyID) {
                    $found = $cert;
                    break;
                }
            }
        }
        if (!$found) {
            throw new CertificateException('CA not found');
        }
        $lazy = $this->data->toArray(false, true);
        $signed = $lazy->rawData()['tbsCertList'];
        $signatureValue = $lazy['signatureValue'];
        $signatureAlgorithm = $lazy['signatureAlgorithm']['algorithm'];
        return $this->validateSignature(
            $this->data->getReader()->chunk($signed['start'], $signed['length']),
            substr($signatureValue, 1),
            $found->getPublicKey(),
            $signatureAlgorithm
        );
    }
    protected function validateSignature($subject, $signature, $public, $algorithm) : bool
    {
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
    public function revoked(bool $extensions = false)
    {
        $temp = $this->data->toArray(false, true)['tbsCertList'];
        if (isset($temp['revokedCertificates'])) {
            foreach ($temp['revokedCertificates']->rawData() as $v) {
                $cert = Decoder::fromString($this->data->getReader()->chunk($v['start'], $v['length']))
                    ->map(Parser::map()['children']['tbsCertList']['children']['revokedCertificates']['repeat']);
                $reason = 0;
                foreach ($cert['extensions'] ?? [] as $ext) {
                    if ($ext['extnID'] === '2.5.29.21') {
                        while (is_array($ext['extnValue'])) {
                            $ext['extnValue'] = array_values($ext['extnValue'])[0];
                        }
                        $reason = (int)$ext['extnValue'];
                    }
                }
                if (!$extensions) {
                    unset($cert['extensions']);
                }
                if ($reason !== 8) {
                    $cert['reason'] = $reason;
                    yield $cert;
                }
            }
        }
    }
    public function isRevoked(string $cert, int $time = null)
    {
        $time = $time ?? time();
        foreach ($this->revoked() as $c) {
            if (trim($c['userCertificate'], '0 ') === trim($cert, '0 ')) {
                return $c['revocationDate'] <= $time;
            }
        }
        return false;
    }
}
