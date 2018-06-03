<?php

namespace X509DS;

/**
 * Class Digest
 *
 * @package X509DS
 */
final class Digest extends AbstractAlgorithm
{
    public const SHA1      = 'http://www.w3.org/2000/09/xmldsig#sha1';
    public const SHA256    = 'http://www.w3.org/2001/04/xmlenc#sha256';
    public const SHA512    = 'http://www.w3.org/2001/04/xmlenc#sha512';
    public const RIPEMD160 = 'http://www.w3.org/2001/04/xmlenc#ripemd160';

    /**
     * @param string
     */
    public function __construct(string $method = self::SHA1)
    {
        $this->setMethod($method);
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
        return openssl_digest($content, $this->extractMethod($this->method), true);
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

    public function getMethods(): array
    {
        return [
            self::SHA1,
            self::SHA256,
            self::SHA512,
            self::RIPEMD160,
        ];
    }
}
