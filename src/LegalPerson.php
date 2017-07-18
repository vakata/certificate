<?php

namespace vakata\certificate;

class LegalPerson extends Person
{
    protected $name;

    public function __construct(string $name, string $idProvider, string $id, string $country = null)
    {
        parent::__construct($idProvider, $id, $country);
        $this->name = $name;
    }
    public function getName() : string
    {
        return $this->name;
    }
    protected function validBulstat(string $value) : bool
    {
        $value = preg_replace('(^BG)', '', $value);
        if (!ctype_digit($value) || !in_array(strlen($value), [ 9, 13 ])) {
            return false;
        }
        $value = str_split($value);
        $sum = 0;
        for ($i = 0; $i < 8; $i++) {
            $sum += $value[$i] * ($i + 1);
        }
        $mod = $sum % 11;
        if ($mod === 10) {
            $sum = 0;
            for ($i = 0; $i < 8; $i++) {
                $sum += $value[$i] * ($i + 3);
            }
            $mod = ($sum % 11) % 10;
        }
        if ((int)$value[8] !== $mod) {
            return false;
        }
        if (isset($value[9])) {
            $sum = $value[8] * 2 + $value[9] * 7 + $value[10] * 3 + $value[11] * 5;
            $mod = $sum % 11;
            if ($mod === 10) {
                $sum = $value[8] * 4 + $value[9] * 9 + $value[10] * 5 + $value[11] * 7;
                $mod = ($sum % 11) % 10;
            }
            if ((int)$value[12] !== $mod) {
                return false;
            }
        }
        return true;
    }
    public function getBulstat()
    {
        return $this->idProvider === 'NTR' && $this->country === 'BG' && $this->validBulstat($this->id) ? $this->id : null;
    }
}