<?php
namespace vakata\certificate\test;

class BGTest extends \PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$cer = \vakata\certificate\Certificate::fromFile(__DIR__ . '/test.crt');

		$this->assertEquals(true, $cer->isPersonal());
		$this->assertEquals(false, $cer->isProfessional());
		$this->assertEquals('1111111110', $cer->getNaturalPerson()->getEGN());
		$this->assertEquals('1111111110', $cer->getNaturalPerson()->getID());
		$this->assertEquals('Ivan Georgiev Bozhanov', $cer->getNaturalPerson()->getName());
		$this->assertEquals('ivan@vakata.com', $cer->getNaturalPerson()->getMail());
		$this->assertEquals(null, $cer->getLegalPerson());
		$this->assertEquals(true, is_array($cer->getData()));
		$this->assertEquals(true, is_array($cer->getSubjectData()));
		$this->assertEquals(true, is_array($cer->getIssuerData()));
	}
}
