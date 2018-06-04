<?php

namespace X509DS\Tests;

use Codeception\Specify;
use PHPUnit\Framework\TestCase;
use X509DS\Canonization;
use X509DS\Digest;
use X509DS\Exception\AlgorithmException;
use X509DS\Exception\InvalidPfxException;
use X509DS\Signature;
use X509DS\Signer;

class SignerTest extends TestCase
{
    use Specify;

    private const PKEY = __DIR__ . '/resources/private.key';
    private const PFX  = __DIR__ . '/resources/test.pfx';
    private const XML  = __DIR__ . '/resources/request.xml';

    public function testFromPrivateKey()
    {
        $this->describe('Signer', function () {
            $this->should('accept a ressource', function () {
                $path     = self::PKEY;
                $resource = openssl_pkey_get_private(file_get_contents($path));
                $signer   = Signer::fromPrivateKey($resource);
                $this->assertInstanceOf(Signer::class, $signer);
            });
            $this->should('accept private key content', function () {
                $path    = self::PKEY;
                $content = file_get_contents($path);
                $signer  = Signer::fromPrivateKey($content);
                $this->assertInstanceOf(Signer::class, $signer);
            });
            $this->should('accept a path to a private key', function () {
                $signer = Signer::fromPrivateKey(self::PKEY);
                $this->assertInstanceOf(Signer::class, $signer);
            });
        });
    }

    public function testFromPfx()
    {
        $this->describe('Signer', function () {
            $this->should('accept a valid pfx path', function () {
                $signer = Signer::fromPfx(self::PFX, 'secret');
                $this->assertInstanceOf(Signer::class, $signer);
            });
            $this->should('accept a valid pfx', function () {
                $signer = Signer::fromPfx(file_get_contents(self::PFX), 'secret');
                $this->assertInstanceOf(Signer::class, $signer);
            });
            $this->should('reject a pfx with invalid password', function () {
                $this->expectException(InvalidPfxException::class);
                $this->expectExceptionMessage('Could not parse pfx');
                Signer::fromPfx(self::PFX, 'wrongpw');
            });
            $this->should('reject an invalid file', function () {
                $this->expectException(InvalidPfxException::class);
                $this->expectExceptionMessage('Could not parse pfx');
                Signer::fromPfx(self::PKEY, 'wrongpw');
            });
        });
    }

    public function testSetDigestMethod()
    {
        $this->describe('Signer', function () {
            $this->should('Set a valid digest method', function () {
                $signer = Signer::fromPrivateKey(self::PKEY);
                $signer->setDigestMethod(Digest::SHA256);
                $this->assertEquals(Digest::SHA256, $signer->getDigestMethod());
            });
            $this->should('Throw an exception on an invalid digest method', function () {
                $this->expectException(AlgorithmException::class);
                $signer = Signer::fromPrivateKey(self::PKEY);
                $signer->setDigestMethod('InvalidMethod');
            });
        });
    }

    public function testSetSignatureMethod()
    {
        $this->describe('Signer', function () {
            $this->should('Set a valid signature method', function () {
                $signer = Signer::fromPrivateKey(self::PKEY);
                $signer->setSignatureMethod(Signature::SHA256);
                $this->assertEquals(Signature::SHA256, $signer->getSignatureMethod());
            });
            $this->should('Throw an exception on an invalid digest method', function () {
                $this->expectException(AlgorithmException::class);
                $signer = Signer::fromPrivateKey(self::PKEY);
                $signer->setSignatureMethod('InvalidMethod');
            });
        });
    }

    public function testSetCanonization()
    {
        $this->describe('Signer', function () {
            $this->should('Set a valid canonization method', function () {
                $signer = Signer::fromPrivateKey(self::PKEY);
                $signer->setCanonization(Canonization::C14N_WITH_COMMENTS);
                $this->assertEquals(Canonization::C14N_WITH_COMMENTS, $signer->getCanonization());
            });
            $this->should('Throw an exception on an invalid digest method', function () {
                $this->expectException(AlgorithmException::class);
                $signer = Signer::fromPrivateKey(self::PKEY);
                $signer->setDigestMethod('InvalidMethod');
            });
        });
    }

    public function testSign()
    {
        $this->describe('Signer', function () {
            $this->should('sign a document', function () {
                $signer = Signer::fromPrivateKey(self::PKEY);
                $signer->setTags(
                    [
                        'Body'                 => '#body',
                        'Timestamp'            => '#timestamp',
                        'BinarySecurityToken'  => '#binarytoken',
                    ]
                );
                $signer->setCanonization(Canonization::C14N_EXCLUSIVE);
                $document = $signer->sign(self::XML);
                $expected = file_get_contents(__DIR__ . '/resources/request_signed.xml');
                $this->assertEquals($expected, $document->saveXML());
            });
            $this->should('run the signing method, without signing tags', function () {
                $signer = Signer::fromPrivateKey(self::PKEY);
                $signer->setTarget('Header');
                $signer->setCanonization(Canonization::C14N_EXCLUSIVE);
                $document = $signer->sign(self::XML);
                $expected = file_get_contents(__DIR__ . '/resources/request.xml');
            });
        });
    }
}
