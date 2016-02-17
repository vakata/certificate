<?php
namespace vakata\certificate\test;

class BGTest extends \PHPUnit_Framework_TestCase
{
	public function testCreate() {
		$cer = \vakata\certificate\BG::fromFile(__DIR__ . '/test.crt');

		$this->assertEquals(true, $cer->isPersonal());
		$this->assertEquals(false, $cer->isProfessional());
		$this->assertEquals('1111111110', $cer->getEGN());
		$this->assertEquals(null, $cer->getPID());
		$this->assertEquals('1111111110', $cer->getID());
		$this->assertEquals(null, $cer->getBulstat());
		$this->assertEquals(true, is_array($cer->getData()));
		$this->assertEquals(true, is_array($cer->getSubjectData()));
		$this->assertEquals(true, is_array($cer->getIssuerData()));
		$this->assertEquals(\vakata\certificate\BG::STAMPIT, $cer->getIssuer());
		$this->assertEquals(\vakata\certificate\BG::PERSONAL, $cer->getType());
	}
}
