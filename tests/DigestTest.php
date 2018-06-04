<?php

namespace X509DS\Tests;

use Codeception\Specify;
use PHPUnit\Framework\TestCase;
use X509DS\Digest;
use X509DS\Exception\AlgorithmException;

class DigestTest extends TestCase
{
    use Specify;

    public function testCalculate()
    {
        $this->describe('Digest', function () {
            $this->should('accept sha1 as a method', function () {
                $sig = new Digest(Digest::SHA1);
                $encrypted = $sig->calculate('this is a test');
                $this->assertEquals(
                    '+ia+Gd5r/5P3C8IwhDTkpEC7rQI=',
                    base64_encode($encrypted)
                );
            });
            $this->should('accept sha256 as a method', function () {
                $sig = new Digest(Digest::SHA256);
                $encrypted = $sig->calculate('this is a test');
                $this->assertEquals(
                    'Lpl1hUiXKo6IIq1H+hAX/3Lwbz/2oBaFH0XDmHMrxQw=',
                    base64_encode($encrypted)
                );
            });
            $this->should('accept sha512 as a method', function () {
                $sig = new Digest(Digest::SHA512);
                $encrypted = $sig->calculate('this is a test');
                $this->assertEquals(
                    'fQqEaO0iBADAuObzNbqn4HDOiAo34qxZlbmpe4CQJt5ibaY2rHNlJJu5dMcZ7fVDtS7ShmRvQ33H+BDMIGg3XA==',
                    base64_encode($encrypted)
                );
            });
            $this->should('accept ripemd160 as a method', function () {
                $sig = new Digest(Digest::RIPEMD160);
                $encrypted = $sig->calculate('this is a test');
                $this->assertEquals(
                    'VzZdtt3guPQhQxT6CbWHuvGzOfg=',
                    base64_encode($encrypted)
                );
            });
            $this->should('throw a AlgorithmException if an unknown method is given', function () {
                $this->expectException(AlgorithmException::class);
                $sig = new Digest('ripemd256');
                $encrypted = $sig->calculate('this is a test');
            });
        });
    }
}
