<?php

namespace vakata\certificate;

class NaturalPerson extends Person
{
    protected $name;
    protected $mail;
    protected $data;

    public function __construct(string $name, string $idProvider, string $id, string $country = null, string $mail = null, array $data = [])
    {
        parent::__construct($idProvider, $id, $country);
        $this->name = $name;
        $this->mail = $mail;
        $this->data = $data;
    }
    public function getName() : string
    {
        return $this->name;
    }
    public function getData() : string
    {
        return $this->data;
    }
    public function getMail()
    {
        return $this->mail;
    }
    protected function validEGN(string $value) : bool
    {
        if (!ctype_digit($value) || strlen($value) !== 10) {
            return false;
        }
        $year  = substr($value, 0, 2);
        $month = substr($value, 2, 2);
        $day   = substr($value, 4, 2);
        if ($month > 40) {
            $month -= 40;
            $year  += 2000;
        } elseif ($month > 20) {
            $month -= 20;
            $year  += 1800;
        } else {
            $year  += 1900;
        }
        if (!checkdate((int)$month, (int)$day, (int)$year)) {
            return false;
        }

        $value = str_split($value);
        $check = array_pop($value);
        $weights = [ 2, 4, 8, 5, 10, 9, 7, 3, 6 ];
        foreach ($value as $k => $v) {
            $value[$k] = $v * $weights[$k];
        }
        return (array_sum($value) % 11) % 10 === (int)$check;
    }
    protected function validLNC(string $value) : bool
    {
        if (!ctype_digit($value) || strlen($value) !== 10) {
            return false;
        }
        $value = str_split($value);
        $check = array_pop($value);
        $weights = [ 21, 19, 17, 13, 11, 9, 7, 3, 1 ];
        foreach ($value as $k => $v) {
            $value[$k] = $v * $weights[$k];
        }
        return array_sum($value) % 10 === (int)$check;
    }
    public function getEGN()
    {
        return $this->idProvider === 'PNO' && $this->country === 'BG' && $this->validEGN($this->id) ? $this->id : null;
    }
    public function getLNC()
    {
        return $this->idProvider === 'PNO' && $this->country === 'BG' && $this->validLNC($this->id) ? $this->id : null;
    }
}