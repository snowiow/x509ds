<?php

namespace X509DS;

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

    public function __construct(string $method = self::SHA1)
    {
        $this->method = $method;
    }

    public function calculate(string $node): string
    {
        switch ($this->method) {
        case self::SHA1:
            return sha1($node, true);
        }
        throw new Exception('Invalid signature method given: ' . $this->method);
    }
}
