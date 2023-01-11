<?php

namespace vakata\certificate;

use vakata\asn1\ASN1;
use vakata\asn1\Decoder;

abstract class Signature
{
    public const VERIFY_MODE = 1;
    public const DECRYPT_MODE = 2;
    public const CLI_MODE = 4;

    protected static $mode = 7;

    public static function setMode(int $mode)
    {
        static::$mode = $mode;
    }
    public static function getMode(): int
    {
        return static::$mode;
    }
    public static function verify(
        string $data,
        string $signature,
        string $publicKey,
        string $algorithm,
        int $mode = null
    ) {
        if ($mode === null) {
            $mode = static::$mode;
        }
        if (preg_match('(^[\d.]+$)', $algorithm)) {
            $algorithm = ASN1::OIDtoText($algorithm);
        }
        if (($mode & static::VERIFY_MODE) && is_callable('\openssl_verify')) {
            try {
                $found = null;
                foreach (openssl_get_md_methods(true) as $a) {
                    if (strtolower($a) === strtolower($algorithm)) {
                        $found = $a;
                        break;
                    }
                }
                if (!isset($found)) {
                    throw new CertificateException('Unsupported algorithm');
                }
                if (openssl_verify($data, $signature, $publicKey, $found) === 1) {
                    return true;
                }
            } catch (\Throwable $ignore) {
                // no need to catch
            }
        }
        if (($mode & static::DECRYPT_MODE) && is_callable('\openssl_public_decrypt')) {
            try {
                $digest = $algorithm;
                $temp = null;
                if (preg_match('((md|sha)-?(\d+))i', strtolower($digest), $temp)) {
                    $digest = $temp[0];
                }
                if (!in_array($digest, hash_algos())) {
                    throw new CertificateException('Unsupported digest algorithm');
                }
                $temp = null;
                if (openssl_public_decrypt($signature, $temp, $publicKey)) {
                    $hash = bin2hex(Decoder::fromString($temp)->values()[0][1]);
                    if (strtolower($hash) === strtolower(hash($digest, $data, false))) {
                        return true;
                    }
                }
            } catch (\Throwable $ignore) {
                // no need to catch
            }
        }
        if (($mode & static::CLI_MODE)) {
            $sig = tempnam(sys_get_temp_dir(), 'openssl_verify_sig');
            $hsh = tempnam(sys_get_temp_dir(), 'openssl_verify_hash');
            $key = tempnam(sys_get_temp_dir(), 'openssl_verify_pkey');
            if ($sig !== false && $hsh !== false && $key !== false) {
                $digest = $algorithm;
                $temp = null;
                if (preg_match('((md|sha)-?(\d+))i', strtolower($digest), $temp)) {
                    $digest = [$temp[0]];
                } else {
                    $digest = ['sha1', 'sha256', 'sha384', 'sha512'];
                }
                file_put_contents($sig, $signature);
                file_put_contents($key, $publicKey);
                $valid = false;
                foreach ($digest as $hash) {
                    file_put_contents($hsh, hash($hash, $data, true));
                    if (
                        exec(
                            'openssl pkeyutl -verify' .
                            ' -in ' . escapeshellarg($hsh) .
                            ' -sigfile ' . escapeshellarg($sig) .
                            ' -pubin -inkey ' . escapeshellarg($key) .
                            ' -pkeyopt digest:' . escapeshellarg($hash)
                        ) === 'Signature Verified Successfully'
                    ) {
                        $valid = true;
                        break;
                    }
                    if (
                        exec(
                            'openssl pkeyutl -verify' .
                            ' -in ' . escapeshellarg($hsh) .
                            ' -sigfile ' . escapeshellarg($sig) .
                            ' -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:-1' .
                            ' -pubin -inkey ' . escapeshellarg($key) .
                            ' -pkeyopt digest:' . escapeshellarg($hash)
                        ) === 'Signature Verified Successfully'
                    ) {
                        $valid = true;
                        break;
                    }
                }
                unlink($hsh);
                unlink($sig);
                unlink($key);
                if ($valid) {
                    return true;
                }
            }
        }
        return false;
    }
}