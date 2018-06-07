<?php

namespace X509DS;

use X509DS\Exceptions\SignatureException;

/**
 * Class Signature
 *
 * @package X509DS
 */
final class Signature extends AbstractAlgorithm
{
    public const SHA1      = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
    public const SHA256    = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    public const SHA512    = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';
    public const RIPEMD160 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160';

    private const OPENSSL_MAPPING = [
        self::SHA1      => OPENSSL_ALGO_SHA1,
        self::SHA256    => OPENSSL_ALGO_SHA256,
        self::SHA512    => OPENSSL_ALGO_SHA512,
        self::RIPEMD160 => OPENSSL_ALGO_RMD160,
    ];

    /**
     * @param string method Signature will be initialized with the given resurce
     */
    public function __construct(string $method = self::SHA1)
    {
        $this->setMethod($method);
    }

    /**
     * Signs the given content with the given private key
     *
     * @param string     $content The content to be signed
     * @param PrivateKey $pkey    The private key used to sign content
     *
     * @return string
     */
    public function calculate(string $content, PrivateKey $pkey): string
    {
        $result = openssl_sign(
            $content,
            $signature,
            $pkey->getResource(),
            self::OPENSSL_MAPPING[$this->getMethod()]
        );

        if ($result === false) {
            throw new SignatureException();
        }

        return base64_encode($signature);
    }

    /**
     * Return a list of all valid methods, with which the algorithm can work
     *
     * @return array
     */
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
