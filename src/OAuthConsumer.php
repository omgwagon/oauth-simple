<?php

namespace Omgwagon\OAuthSimple;

class OAuthConsumer
{
    private $secrets;
    private $default_signature_method;
    private $action;
    private $nonce_chars;
    private $parameters;
    private $path;
    private $signature_base_string;
    private $oauth_body_hash;

    /**
     * Constructor
     *
     * @access public
     * @param string $api_key
     * @param string $shared_secret
     * @return OAuthConsumer
     * @throws OAuthSimpleException
     */
    public function setup($api_key = "", $shared_secret = "")
    {
        if (!empty($api_key)) {
            $this->secrets['consumer_key'] = $api_key;
        }
        if (!empty($shared_secret)) {
            $this->secrets['shared_secret'] = $shared_secret;
        }
        $this->default_signature_method = "HMAC-SHA1";
        $this->setAction('GET');
        $this->nonce_chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
        return $this;
    }

    /**
     * @param $params
     * @param $url
     * @return array
     * @throws OAuthSimpleException
     */
    public function signParams($params, $url)
    {
        // Parse the passed in $url string
        $parse_url = parse_url($url);

        // Pull out the query string
        $query_part = isset($parse_url['query']) ? $parse_url['query'] : '';

        // Pull out the path part
        $path_part = isset($parse_url['path']) ? $parse_url['path'] : '';

        // Parse the query string into and array
        $query_params = array();
        parse_str($query_part, $query_params);

        // Reset any left over auth data
        $this->reset();

        // Strip out ports 80 or 443 as per oauth spec and build url without query
        $port = isset($parse_url['port']) ? ':' . $parse_url['port'] : '';
        $this->setUrl(
            preg_replace(
                '/:80|:443/',
                '',
                $parse_url['scheme'] . '://' . $parse_url['host'] . $port . $path_part
            )
        );

        // Set both the POST params and query params to be signed
        $this->setParameters(array_merge($params, $query_params));

        // Return the params and oauth params as an array map
        return array_merge($params, $this->getParamArray($params));
    }

    /**
     * Reset the parameters and URL
     *
     * @access public
     * @return OAuthConsumer (Object)
     */
    public function reset()
    {
        $this->parameters = array();
        $this->setPath(null);
        $this->setSignatureBaseString(null);
        return $this;
    }

    /**
     * Generate and set an oauth_body_hash from the request body.
     *
     * @param $body
     */
    public function genBodyHash($body)
    {
        $this->oauth_body_hash = base64_encode(sha1($body, true));
    }

    /**
     * Set the parameters either from a hash or a string
     *
     * @access public
     * @param array - An array of parameters for the call
     * @return OAuthConsumer (Object)
     * @throws OAuthSimpleException
     */
    private function setParameters($parameters = array())
    {
        if (empty($this->parameters)) {
            $this->parameters = $parameters;
        }
        if (empty($this->parameters['oauth_nonce'])) {
            $this->setNonceParameter();
        }
        if (empty($this->parameters['oauth_timestamp'])) {
            $this->getTimeStamp();
        }
        if (empty($this->parameters['oauth_consumer_key'])) {
            $this->getApiKey();
        }
        if (empty($this->parameters['oauth_token'])) {
            $this->getAccessToken();
        }
        if (empty($this->parameters['oauth_signature_method'])) {
            $this->setSignatureMethod();
        }
        if (empty($this->parameters['oauth_version'])) {
            $this->parameters['oauth_version'] = "1.0";
        }
        if (isset($this->oauth_body_hash)) {
            $this->parameters['oauth_body_hash'] = $this->oauth_body_hash;
        }
        return $this;
    }

    /**
     * @return mixed
     */
    public function getParameters()
    {
        return $this->parameters;
    }

    /**
     * Set the target URL (does not include the parameters)
     *
     * @throws OAuthSimpleException
     * @param string - The fully qualified URI (excluding query arguments) (e.g "http://example.org/foo")
     * @return OAuthConsumer (Object)
     */
    public function setURL($path)
    {
        if (empty($path)) {
            throw new OAuthSimpleException('No path specified for OAuthSimple.setURL');
        }
        $this->path = $path;
        return $this;
    }

    /**
     * Convenience method for setURL
     *
     * @param $path (String)
     * @see setURL
     * @return mixed
     */
    public function setPath($path)
    {
        return $this->path = $path;
    }

    /**
     * @return mixed
     */
    public function getPath()
    {
        return $this->path;
    }

    /**
     * @return mixed
     */
    public function getSignatureBaseString()
    {
        return $this->signature_base_string;
    }

    /**
     * @param mixed $signature_base_string
     */
    private function setSignatureBaseString($signature_base_string)
    {
        $this->signature_base_string = $signature_base_string;
    }

    /**
     * Set the "action" for the url, (e.g. GET,POST, DELETE, etc.)
     *
     * @param $action (String) HTTP Action word.
     * @return OAuthConsumer
     * @throws OAuthSimpleException
     */
    public function setAction($action)
    {
        if (empty($action)) {
            $action = 'GET';
        }
        $action = strtoupper($action);
        if (preg_match('/[^A-Z]/', $action)) {
            throw new OAuthSimpleException('Invalid action specified for OAuthSimple.setAction');
        }
        $this->action = $action;
        return $this;
    }

    /**
     * @return mixed
     */
    public function getAction()
    {
        return $this->action;
    }

    /**
     * Set the signatures (as well as validate the ones you have)
     *
     * @param array - Hash of the token/signature pairs {api_key:, shared_secret:, oauth_token: oauth_secret:}
     * @return OAuthConsumer
     * @throws OAuthSimpleException
     */
    private function signatures($signatures)
    {
        if (!empty($signatures) && !is_array($signatures)) {
            throw new OAuthSimpleException('Must pass dictionary array to OAuthSimple.signatures');
        }
        if (!empty($signatures)) {
            if (empty($this->secrets)) {
                $this->secrets = array();
            }
            $this->secrets = array_merge($this->secrets, $signatures);
        }
        if (isset($this->secrets['api_key'])) {
            $this->secrets['consumer_key'] = $this->secrets['api_key'];
        }
        if (isset($this->secrets['access_token'])) {
            $this->secrets['oauth_token'] = $this->secrets['access_token'];
        }
        if (isset($this->secrets['access_secret'])) {
            $this->secrets['oauth_secret'] = $this->secrets['access_secret'];
        }
        if (isset($this->secrets['access_token_secret'])) {
            $this->secrets['oauth_secret'] = $this->secrets['access_token_secret'];
        }
        if (empty($this->secrets['consumer_key'])) {
            throw new OAuthSimpleException('Missing required consumer_key in OAuthSimple.signatures');
        }
        if (empty($this->secrets['shared_secret'])) {
            throw new OAuthSimpleException('Missing required shared_secret in OAuthSimple.signatures');
        }
        if (!empty($this->secrets['oauth_token']) && empty($this->secrets['oauth_secret'])) {
            throw new OAuthSimpleException('Missing oauth_secret for supplied oauth_token in OAuthSimple.signatures');
        }
        return $this;
    }


    /**
     * Set Tokens and Secrets
     *
     * @param $signatures
     * @return OAuthConsumer
     * @throws OAuthSimpleException
     */
    public function setTokensAndSecrets($signatures)
    {
        return $this->signatures($signatures);
    }

    /**
     * Set the signature method (currently only Plaintext or HMAC-SHA1)
     *
     * @param string $method
     * @return OAuthConsumer
     * @throws OAuthSimpleException
     * @internal param method $Method of signing the transaction (only PLAINTEXT and HMAC-SHA1 allowed for now)
     */
    public function setSignatureMethod($method = "")
    {
        if (empty($method)) {
            $method = $this->default_signature_method;
        }
        $method = strtoupper($method);
        switch ($method) {
            case 'PLAINTEXT':
            case 'HMAC-SHA1':
                $this->parameters['oauth_signature_method'] = $method;
                break;
            default:
                throw new OAuthSimpleException(
                    "Unknown signing method $method specified for OAuthSimple.setSignatureMethod"
                );
                break;
        }
        return $this;
    }

    /** sign the request
     *
     * @return array (Array) signed values
     * @throws OAuthSimpleException
     */
    public function sign()
    {
        $parameters = array();
        $this->setParameters($parameters);
        $normParams = $this->normalizedParameters();
        $this->parameters['oauth_signature'] = $this->generateSignature($normParams);
        return array(
            'parameters' => $this->parameters,
            'signature' => self::oauthEscape($this->parameters['oauth_signature']),
            'signed_url' => $this->getPath() . '?' . $this->normalizedParameters(),
            'header' => $this->getHeaderString(),
            'sbs' => $this->getSignatureBaseString()
        );
    }

    /**
     * Return a formatted "header" string
     *
     * NOTE: This doesn't set the "Authorization: " prefix, which is required.
     * It's not set because various set header functions prefer different
     * ways to do that.
     *
     * @param array $args
     * @return mixed $result (String)
     * @internal param $args (Array)
     * @throws OAuthSimpleException
     */
    public function getHeaderString($args = array())
    {
        if (empty($this->parameters['oauth_signature'])) {
            $this->sign($args);
        }
        $result = 'OAuth ';
        foreach ($this->parameters as $pName => $pValue) {
            if (strpos($pName, 'oauth_') !== 0) {
                continue;
            }
            $result .= $pName . '="' . self::oauthEscape($pValue) . '", ';
        }
        return preg_replace('/, $/', '', $result);
    }

    /**
     * @param array $args
     * @return array
     * @throws OAuthSimpleException
     */
    public function getParamArray($args = array())
    {
        if (empty($this->parameters['oauth_signature'])) {
            $this->sign($args);
        }
        $result = array();
        foreach ($this->parameters as $pName => $pValue) {
            if (strpos($pName, 'oauth_') !== 0) {
                continue;
            }
            $result[$pName] = self::oauthEscape($pValue);
        }
        return $result;
    }

    /**
     * @param $string
     * @return int|mixed|string
     */
    private static function oauthEscape($string)
    {
        if ($string === 0) {
            return 0;
        }
        if (strlen($string) == 0) {
            return '';
        }
        $string = rawurlencode($string);
        $string = str_replace('+', '%20', $string);
        $string = str_replace('!', '%21', $string);
        $string = str_replace('*', '%2A', $string);
        $string = str_replace('\'', '%27', $string);
        $string = str_replace('(', '%28', $string);
        $string = str_replace(')', '%29', $string);
        return $string;
    }

    /**
     * @param int $length
     * @return string
     */
    private function setNonceParameter($length = 5)
    {
        $result = '';
        $cLength = strlen($this->nonce_chars);
        for ($i = 0; $i < $length; $i++) {
            $rnum = rand(0, $cLength);
            $result .= substr($this->nonce_chars, $rnum, 1);
        }
        $this->parameters['oauth_nonce'] = sha1($result);
        return $result;
    }

    /**
     * @return mixed
     * @throws OAuthSimpleException
     */
    private function getApiKey()
    {
        if (empty($this->secrets['consumer_key'])) {
            throw new OAuthSimpleException('No consumer_key set for OAuthSimple');
        }
        $this->parameters['oauth_consumer_key'] = $this->secrets['consumer_key'];
        return $this->parameters['oauth_consumer_key'];
    }

    /**
     * @return string
     * @throws OAuthSimpleException
     */
    private function getAccessToken()
    {
        if (!isset($this->secrets['oauth_secret'])) {
            return '';
        }
        if (!isset($this->secrets['oauth_token'])) {
            throw new OAuthSimpleException('No access token (oauth_token) set for OAuthSimple.');
        }
        $this->parameters['oauth_token'] = $this->secrets['oauth_token'];
        return $this->parameters['oauth_token'];
    }

    /**
     * @return int
     */
    private function getTimeStamp()
    {
        return $this->parameters['oauth_timestamp'] = time();
    }

    /**
     * @return string
     */
    private function normalizedParameters()
    {
        $normalized_keys = array();
        $return_array = array();
        foreach ($this->parameters as $paramName => $paramValue) {
            if (!preg_match('/\w+_secret/', $paramName)
                || (strpos($paramValue, '@') !== 0 && !file_exists(substr($paramValue, 1)))) {
                if (is_array($paramValue)) {
                    $normalized_keys[self::oauthEscape($paramName)] = array();
                    foreach ($paramValue as $item) {
                        array_push($normalized_keys[self::oauthEscape($paramName)], self::oauthEscape($item));
                    }
                } else {
                    $normalized_keys[self::oauthEscape($paramName)] = self::oauthEscape($paramValue);
                }
            }
        }
        ksort($normalized_keys);
        foreach ($normalized_keys as $key => $val) {
            if (is_array($val)) {
                sort($val);
                foreach ($val as $element) {
                    array_push($return_array, $key . "=" . $element);
                }
            } else {
                array_push($return_array, $key . '=' . $val);
            }
        }
        return join("&", $return_array);
    }

    /**
     * @return string
     */
    private function generateSignature()
    {
        $secretKey = '';
        if (isset($this->secrets['shared_secret'])) {
            $secretKey = self::oauthEscape($this->secrets['shared_secret']);
        }
        $secretKey .= '&';
        if (isset($this->secrets['oauth_secret'])) {
            $secretKey .= self::oauthEscape($this->secrets['oauth_secret']);
        }
        $signature = '';
        switch ($this->parameters['oauth_signature_method']) {
            case 'PLAINTEXT':
                $signature = urlencode($secretKey);
                break;
            case 'HMAC-SHA1':
                $this->setSignatureBaseString(
                    self::oauthEscape($this->getAction()) .
                    '&' .
                    self::oauthEscape($this->getPath()) .
                    '&' .
                    self::oauthEscape($this->normalizedParameters())
                );
                $signature = base64_encode(hash_hmac('sha1', $this->getSignatureBaseString(), $secretKey, true));
                break;
        }
        return $signature;
    }
}
