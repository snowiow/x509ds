<?php

namespace X509DS\Tests;

use Codeception\Specify;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use X509DS\Exception\FileNotFoundException;
use X509DS\Exception\InvalidKeyException;
use X509DS\PrivateKey;

class PrivateKeyTest extends TestCase
{
    use Specify;

    public function testFromResource()
    {
        $this->describe('PrivateKey', function () {
            $this->should('accept a valid private key', function () {
                $path     = __DIR__ . '/resources/private.key';
                $resource = openssl_pkey_get_private(file_get_contents($path));
                $pkey     = PrivateKey::fromResource($resource);
                $this->assertInstanceOf(PrivateKey::class, $pkey);
            });
            $this->should('throw an InvalidArgumException an a non resource', function () {
                $this->expectException(InvalidArgumentException::class);
                $this->expectExceptionMessage('Argument must be a valid resource type. string given.');
                PrivateKey::fromResource('this is a string');
            });
        });
    }

    public function testFromContent()
    {
        $this->describe('PrivateKey', function () {
            $this->should('accept the content of a valid private key', function () {
                $path    = __DIR__ . '/resources/private.key';
                $content = file_get_contents($path);
                $pkey    = PrivateKey::fromContent($content);
                $this->assertInstanceOf(PrivateKey::class, $pkey);
            });
            $this->should('accept the content of a valid private key with password', function () {
                $path    = __DIR__ . '/resources/private_with_pw.key';
                $content = file_get_contents($path);
                $pkey    = PrivateKey::fromContent($content, 'secret');
                $this->assertInstanceOf(PrivateKey::class, $pkey);
            });
            $this->should('decline the content of an invalid private key', function () {
                $this->expectException(InvalidKeyException::class);
                $this->expectExceptionMessage('Could not parse key');
                $content = 'some nonesense string';
                PrivateKey::fromContent($content);
            });
            $this->should('decline the content of a valid private key with invalid password', function () {
                $this->expectException(InvalidKeyException::class);
                $this->expectExceptionMessage('Could not parse key');
                $path    = __DIR__ . '/resources/private_with_pw.key';
                $content = file_get_contents($path);
                PrivateKey::fromContent($content, 'wrongpw');
            });
        });
    }

    public function testFromPath()
    {
        $this->describe('PrivateKey', function () {
            $this->should('accept the path of a valid private key', function () {
                $pkey = PrivateKey::fromPath(__DIR__ . '/resources/private.key');
                $this->assertInstanceOf(PrivateKey::class, $pkey);
            });
            $this->should('accept the content of a valid path with password', function () {
                $pkey = PrivateKey::fromPath(__DIR__ . '/resources/private_with_pw.key', 'secret');
                $this->assertInstanceOf(PrivateKey::class, $pkey);
            });
            $this->should('decline the path of an invalid private key', function () {
                $path = '/var/www/test.key';
                $this->expectException(FileNotFoundException::class);
                $this->expectExceptionMessage('File not found: ' . $path);
                PrivateKey::fromPath($path);
            });
            $this->should('decline the path of a valid private key with invalid password', function () {
                $this->expectException(InvalidKeyException::class);
                $this->expectExceptionMessage('Could not parse key');
                $path = __DIR__ . '/resources/private_with_pw.key';
                PrivateKey::fromPath($path, 'wrongpw');
            });
        });
    }
}
