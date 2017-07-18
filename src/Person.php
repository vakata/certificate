<?php

namespace vakata\certificate;

abstract class Person
{
    protected $idProvider;
    protected $country;
    protected $id;
    
    public function __construct(string $idProvider, string $id, string $country = null)
    {
        $this->idProvider = $idProvider;
        $this->country = $country;
        $this->id = $id;
    }
    public function getProvider() : string
    {
        return $this->idProvider;
    }
    public function getID() : string
    {
        return $this->id;
    }
    public function getCountry()
    {
        return $this->country;
    }
}