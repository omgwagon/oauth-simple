<?php

namespace OmgWagon\OAuthSimple\Tests;

use Omgwagon\OAuthSimple\OAuthConsumer;
use Omgwagon\OAuthSimple\OAuthSimpleException;
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
        try {
            $oauth->setup(self::CONSUMER_KEY, self::SECRET);
            $oauth->setAction('POST');
            $oauth->setPath('/test');
            $oauth->setSignatureMethod('HMAC-SHA1');
            $oauth->signParams(array('test' => 'test'), self::URL);
        } catch (OAuthSimpleException $e) {
        }

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
        try {
            $oauth->setup(self::CONSUMER_KEY, self::SECRET);
            $oauth->setAction('POST');
            $oauth->setPath('/test');
            $oauth->setSignatureMethod('HMAC-SHA1');
            $oauth->signParams(array(
                'test' => 'test',
                0 => 'test',
            ), self::URL);
        } catch (OAuthSimpleException $e) {
        }
        $parameters = $oauth->getParameters();

        $this->assertArrayHasKey('oauth_signature', $parameters);
        $this->assertArrayHasKey('test', $parameters);
        $this->assertArrayHasKey(0, $parameters);
    }

    public function testThatBodyHashIsGeneratedAndInHeader()
    {
        $oauth = new OAuthConsumer();
        try {
            $oauth->setup(self::CONSUMER_KEY, self::SECRET);
            $oauth->genBodyHash(self::TEST_BODY);
        } catch (OAuthSimpleException $e) {
        }
        $this->assertRegexp('/oauth_body_hash/', $oauth->getHeaderString());
    }

    /**
     * @expectedException Omgwagon\OAuthSimple\OAuthSimpleException
     * @expectedExceptionMessageRegExp /No path specified for OAuthSimple.setURL/
     * @throws OAuthSimpleException
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
        try {
            $oauth->setup(self::CONSUMER_KEY, self::SECRET);
            $oauth->setAction('');
        } catch (OAuthSimpleException $e) {
        }
        $this->assertEquals($oauth->getAction(), 'GET');
    }

    /**
     * @expectedException Omgwagon\OAuthSimple\OAuthSimpleException
     * @expectedExceptionMessageRegExp /Invalid action specified for OAuthSimple.setAction/
     * @throws \Omgwagon\OAuthSimple\OAuthSimpleException
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
     * @throws \Omgwagon\OAuthSimple\OAuthSimpleException
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
     * @throws \Omgwagon\OAuthSimple\OAuthSimpleException
     */
    public function testThatNoApiKeyThrowsException()
    {
        $oauth = new OAuthConsumer();
        $oauth->signParams(array('test' => 'test'), self::URL);
    }

    /**
     * @expectedException Omgwagon\OAuthSimple\OAuthSimpleException
     * @expectedExceptionMessageRegExp /No access token \(oauth_token\) set for OAuthSimple/
     * @throws \Omgwagon\OAuthSimple\OAuthSimpleException
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
     * @expectedExceptionMessageRegExp /Missing required consumer_key in OAuthSimple.signatures/
     * @throws \Omgwagon\OAuthSimple\OAuthSimpleException
     */
    public function testThatNoConsumerKeyThrowsException()
    {
        $oauth = new OAuthConsumer();
        $oauth->setTokensAndSecrets(
            array(
                'shared_secret' => self::SECRET,
                'oauth_secret' => self::SECRET,
            )
        );
        $oauth->signParams(array('test' => 'test'), self::URL);
    }

    /**
     * @expectedException Omgwagon\OAuthSimple\OAuthSimpleException
     * @expectedExceptionMessageRegExp /Missing required shared_secret in OAuthSimple.signatures/
     * @throws \Omgwagon\OAuthSimple\OAuthSimpleException
     */
    public function testThatNoSharedSecretThrowsException()
    {
        $oauth = new OAuthConsumer();
        $oauth->setTokensAndSecrets(
            array(
                'oauth_secret' => self::SECRET,
                'consumer_key' => self::CONSUMER_KEY,
            )
        );
        $oauth->signParams(array('test' => 'test'), self::URL);
    }

    /**
     * @expectedException Omgwagon\OAuthSimple\OAuthSimpleException
     * @expectedExceptionMessageRegExp /Missing oauth_secret for supplied oauth_token in OAuthSimple.signatures/
     * @throws \Omgwagon\OAuthSimple\OAuthSimpleException
     */
    public function testThatOAuthTokenRequiresOAuthSecretThrowsException()
    {
        $oauth = new OAuthConsumer();
        $oauth->setTokensAndSecrets(
            array(
                'oauth_token' => self::ACCESS_TOKEN,
                'shared_secret' => self::SECRET,
                'consumer_key' => self::CONSUMER_KEY,
            )
        );
        $oauth->signParams(array('test' => 'test'), self::URL);
    }

    /**
     * @expectedException Omgwagon\OAuthSimple\OAuthSimpleException
     * @expectedExceptionMessageRegExp /Must pass dictionary array to OAuthSimple.signatures/
     * @throws OAuthSimpleException
     */
    public function testThatEmptyTokenAndSecretsThrowsException()
    {
        $oauth = new OAuthConsumer();
        $oauth->setTokensAndSecrets('bad');
    }

    public function testThatApiKeyBecomesConsumerKey()
    {
        $oauth = new OAuthConsumer();
        $oauth->setTokensAndSecrets(
            array(
                'shared_secret' => self::SECRET,
                'api_key' => self::CONSUMER_KEY,
            )
        );
        $oauth->signParams(array(
            'oauth_signature_method' => 'HMAC-SHA1'
        ), self::URL);

        $this->assertEquals($oauth->getParameters()['oauth_consumer_key'], self::CONSUMER_KEY);
    }

    public function testThatAccessTokenBecomesOAuthToken()
    {
        $oauth = new OAuthConsumer();
        $oauth->setTokensAndSecrets(
            array(
                'shared_secret' => self::SECRET,
                'access_secret' => self::SECRET,
                'access_token' => self::ACCESS_TOKEN,
                'consumer_key' => self::CONSUMER_KEY,
            )
        );
        $oauth->signParams(array(
            'oauth_signature_method' => 'HMAC-SHA1'
        ), self::URL);

        $this->assertEquals($oauth->getParameters()['oauth_token'], self::ACCESS_TOKEN);
    }

    public function testThatAccessTokenSecretBecomesOAuthSecret()
    {
        $oauth = new OAuthConsumer();
        $oauth->setTokensAndSecrets(
            array(
                'shared_secret' => self::SECRET,
                'access_token_secret' => self::SECRET,
                'access_token' => self::ACCESS_TOKEN,
                'consumer_key' => self::CONSUMER_KEY,
            )
        );
        $oauth->signParams(array(
            'oauth_signature_method' => 'HMAC-SHA1'
        ), self::URL);

        $this->assertEquals($oauth->getParameters()['oauth_token'], self::ACCESS_TOKEN);
    }

    public function testThatNormalizedParametersNormalizesArrayValue()
    {
        $oauth = new OAuthConsumer();
        $oauth->setup( self::CONSUMER_KEY, self::SECRET );
        $oauth->signParams(array(
            'test_array' => array(
                'test1' => 'value',
                'test2' => 'value',
            )
        ), self::URL);

        $this->assertArrayHasKey('test1', $oauth->getParameters()['test_array']);
        $this->assertArrayHasKey('test2', $oauth->getParameters()['test_array']);
    }

    public function testThatPlaintextSignatureMethodUrlEncodesSecret()
    {
        $secret = '/test/secret@here';
        $oauth = new OAuthConsumer();
        $oauth->setTokensAndSecrets(
            array(
                'shared_secret' => $secret,
                'consumer_key' => self::CONSUMER_KEY,
            )
        );
        $oauth->signParams(array(
            'oauth_signature_method' => 'PLAINTEXT',
        ), self::URL);

        $this->assertEquals(urlencode($secret) . '&', urldecode($oauth->getParameters()['oauth_signature']));
    }
}
