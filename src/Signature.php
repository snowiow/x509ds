<?php

namespace X509DS;

use Exception;

/**
 * Class Signature
 *
 * @package X509DS
 */
final class Signature extends AbstractAlgorithm
{
    const SHA1      = 'http://www.w3.org/2000/09/xmldsig#sha1';
    const SHA256    = 'http://www.w3.org/2001/04/xmlenc#sha256';
    const SHA512    = 'http://www.w3.org/2001/04/xmlenc#sha512';
    const RIPEMD160 = 'http://www.w3.org/2001/04/xmlenc#ripemd160';

    const METHODS = [
        self::SHA1,
        self::SHA256,
        self::SHA512,
        self::RIPEMD160,
    ];

    /**
     * @param string
     */
    public function __construct(string $method = self::SHA1)
    {
        $this->method = $method;
    }

    /**
     * Calculates the digest hast of the given content
     *
     * @param string $content the content to be hashed
     *
     * @return string the raw output of the hashed content
     */
    public function calculate(string $content): string
    {
        if (in_array($this->method, self::METHODS)) {
            return openssl_digest($content, $this->extractMethod($this->method), true);
        }
        throw new Exception('Invalid signature method given: ' . $this->method);
    }

    /**
     * Takes a xml namespace and extracts the method from it
     *
     * @param string $namespace
     *
     * @return string
     */
    private function extractMethod(string $namespace): string
    {
        return explode('#', $namespace)[1];
    }
}
