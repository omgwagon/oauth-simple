<?php

namespace OmgWagon\OAuthSimple\Tests;

use Omgwagon\OAuthSimple\OAuthSimpleException;
use PHPUnit\Framework\TestCase;

class OAuthSimpleExceptionTest extends TestCase
{
    private static $error_log_config;

    public static function setUpBeforeClass()
    {
        self::$error_log_config = ini_get("error_log");
        ini_set("error_log", "/dev/null");
    }

    public static function tearDownAfterClass()
    {
        ini_set('error_log', self::$error_log_config);
    }

    /**
     * @expectedException Omgwagon\OAuthSimple\OAuthSimpleException
     * @expectedExceptionMessageRegExp /Test Exception/
     */
    public function testThatExceptionHasCorrectMessage()
    {
        throw new OAuthSimpleException('Test Exception');
    }

    public function testThatDebuggingOutputsDetails()
    {
        try {
            throw new OAuthSimpleException('Test Exception', true);
        } catch (OAuthSimpleException $e) {
            $this->assertRegexp('/Test Exception/', $e->getMessage());
            $this->expectOutputRegex('/Test Exception/');
        }
    }
}
