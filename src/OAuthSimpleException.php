<?php

namespace Omgwagon\OAuthSimple;

class OAuthSimpleException extends \Exception
{

    /**
     * OAuthSimpleException constructor.
     * @param string $err
     * @param bool $isDebug
     */
    public function __construct($err, $isDebug = false)
    {
        $this->message = $err;
        self::logError($err);
        if ($isDebug) {
            self::displayError($err, true);
        }
    }

    /**
     * @param $err
     */
    public static function logError($err)
    {
        error_log('OAuthSimpleException: ' . $err, 0);
    }

    /**
     * @param $err
     * @param bool $kill
     */
    public static function displayError($err, $kill = false)
    {
        print_r($err);
    }
}
