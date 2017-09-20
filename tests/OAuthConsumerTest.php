<?php

namespace OmgWagon\OAuthSimple\Tests;

use Omgwagon\OAuthSimple\OAuthConsumer;
use PHPUnit\Framework\TestCase;

class OAuthConsumerTest extends TestCase
{

    private static $error_log_config;

    const CONSUMER_KEY = 'consumer';
    const SECRET = 'secret';
    const ACCESS_TOKEN = 'token';
    const TEST_BODY = '<xml>test</xml>';
    const URL = 'http://test.example.com';

    public static function setUpBeforeClass()
    {
        self::$error_log_config = ini_get("error_log");
        ini_set("error_log", "/dev/null");
    }

    public static function tearDownAfterClass()
    {
        ini_set('error_log', self::$error_log_config);
    }

    public function testThatSetupReturnsCorrectDetailsInHeader()
    {
        $oauth = new OAuthConsumer();
        $oauth->setup(self::CONSUMER_KEY, self::SECRET);
        $oauth->setAction('POST');
        $oauth->setPath('/test');
        $oauth->setSignatureMethod('HMAC-SHA1');
        $oauth->signParams(array('test' => 'test'), self::URL);

        $this->assertRegexp('/oauth_signature/', $oauth->getHeaderString());
        $this->assertRegexp('/oauth_nonce/', $oauth->getHeaderString());
        $this->assertRegexp('/oauth_timestamp/', $oauth->getHeaderString());
        $this->assertRegexp('/oauth_consumer_key/', $oauth->getHeaderString());
        $this->assertRegexp('/oauth_signature_method/', $oauth->getHeaderString());
        $this->assertRegexp('/oauth_version/', $oauth->getHeaderString());
    }

    public function testThatSetupReturnsCorrectDetailsInParameters()
    {
        $oauth = new OAuthConsumer();
        $oauth->setup(self::CONSUMER_KEY, self::SECRET);
        $oauth->setAction('POST');
        $oauth->setPath('/test');
        $oauth->setSignatureMethod('HMAC-SHA1');
        $oauth->signParams(array(
            'test' => 'test',
            0 => 'test',
        ), self::URL);

        $parameters = $oauth->getParameters();

        $this->assertArrayHasKey('oauth_signature', $parameters);
        $this->assertArrayHasKey('test', $parameters);
        $this->assertArrayHasKey(0, $parameters);
    }

    public function testThatBodyHashIsGeneratedAndInHeader()
    {
        $oauth = new OAuthConsumer();
        $oauth->setup(self::CONSUMER_KEY, self::SECRET);
        $oauth->genBodyHash(self::TEST_BODY);

        $this->assertRegexp('/oauth_body_hash/', $oauth->getHeaderString());
    }

    /**
     * @expectedException Omgwagon\OAuthSimple\OAuthSimpleException
     * @expectedExceptionMessageRegExp /No path specified for OAuthSimple.setURL/
     */
    public function testThatBlankUrlThrowsException()
    {
        $oauth = new OAuthConsumer();
        $oauth->setup(self::CONSUMER_KEY, self::SECRET);
        $oauth->setUrl('');
    }

    public function testThatBlankActionBecomesGet()
    {
        $oauth = new OAuthConsumer();
        $oauth->setup(self::CONSUMER_KEY, self::SECRET);
        $oauth->setAction('');
        $this->assertEquals($oauth->getAction(), 'GET');
    }

    /**
     * @expectedException Omgwagon\OAuthSimple\OAuthSimpleException
     * @expectedExceptionMessageRegExp /Invalid action specified for OAuthSimple.setAction/
     */
    public function testThatInvlidActionThrowsException()
    {
        $oauth = new OAuthConsumer();
        $oauth->setup(self::CONSUMER_KEY, self::SECRET);
        $oauth->setAction('12345');
    }

    /**
     * @expectedException Omgwagon\OAuthSimple\OAuthSimpleException
     * @expectedExceptionMessageRegExp /Unknown signing method/
     */
    public function testThatInvlidSignatureMethodThrowsException()
    {
        $oauth = new OAuthConsumer();
        $oauth->setup(self::CONSUMER_KEY, self::SECRET);
        $oauth->setSignatureMethod('12345');
    }

    /**
     * @expectedException Omgwagon\OAuthSimple\OAuthSimpleException
     * @expectedExceptionMessageRegExp /No consumer_key set for OAuthSimple/
     */
    public function testThatNoApiKeyThrowsException()
    {
        $oauth = new OAuthConsumer();
        $oauth->signParams(array('test' => 'test'), self::URL);
    }

    /**
     * @expectedException Omgwagon\OAuthSimple\OAuthSimpleException
     * @expectedExceptionMessageRegExp /No access token \(oauth_token\) set for OAuthSimple/
     */
    public function testThatNoAccessTokenThrowsException()
    {
        $oauth = new OAuthConsumer();
        $oauth->setTokensAndSecrets(
            array(
                'shared_secret' => self::SECRET,
                'oauth_secret' => self::SECRET,
                'consumer_key' => self::CONSUMER_KEY,
            )
        );
        $oauth->signParams(array('test' => 'test'), self::URL);
    }

    /**
     * @expectedException Omgwagon\OAuthSimple\OAuthSimpleException
     * @expectedExceptionMessageRegExp /Must pass dictionary array to OAuthSimple.signatures/
     */
    public function testThatEmptyTokenAndSecretsThrowsException()
    {
        $oauth = new OAuthConsumer();
        $oauth->setTokensAndSecrets('bad');
    }
}
