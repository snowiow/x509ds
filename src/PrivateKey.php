<?php

namespace X509DS;

use InvalidArgumentException;
use X509DS\Exceptions\FileNotFoundException;
use X509DS\Exceptions\InvalidKeyException;

/**
 * Class PrivateKey
 *
 * @package Xml509Ds
 */
final class PrivateKey
{
    /**
     * @var resource
     */
    private $resource;

    /**
     * Create a PrivateKey from an openssl resource
     *
     * @param resource $resource the openssl resource
     *
     * @return PrivateKey
     */
    public static function fromResource($resource): self
    {
        return new self($resource);
    }

    /**
     * Parses a private key from the given file content and password
     *
     * @param string $content  the key content
     * @param string $password
     * @throw InvalidKeyException if the key can't be parsed
     *
     * @return PrivateKey
     */
    public static function fromContent(string $content, string $password = ''): self
    {
        $resource = openssl_pkey_get_private($content, $password);
        if ($resource === false) {
            throw new InvalidKeyException();
        }

        return self::fromResource($resource);
    }

    /**
     * Parses a PrivateKey from the given file path and password
     *
     * @param string $path     the path to the private key file
     * @param string $password
     * @throw FileNotFoundException if the file doesn't exist or can't be read
     *
     * @return PrivateKey
     */
    public static function fromPath(string $path, string $password = ''): self
    {
        $content = false;
        if (file_exists($path)) {
            $content = file_get_contents($path);
        }

        if ($content === false) {
            throw new FileNotFoundException($path);
        }

        return self::fromContent($content, $password);
    }

    private function __construct($resource)
    {
        $this->assertResource($resource);
        $this->resource = $resource;
    }

    public function __destruct()
    {
        openssl_free_key($this->resource);
    }

    public function sign(string $content): string
    {
        $result = openssl_sign($content, $signature, $this->resource);

        if ($result === false) {
            throw new SignatureException();
        }

        return $signature;
    }

    private function assertResource($resource): void
    {
        if (is_resource($resource) == false) {
            throw new InvalidArgumentException(
                sprintf(
                    'Argument must be a valid resource type. %s given.',
                    gettype($resource)
                )
            );
        }
    }
}
