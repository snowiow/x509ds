<?php

namespace X509DS\Tests;

use Codeception\Specify;
use Exception;
use PHPUnit\Framework\TestCase;
use X509DS\Signature;

class SignatureTest extends TestCase
{
    use Specify;

    public function testCalculate()
    {
        $this->describe('Signature', function () {
            $this->should('accept sha1 as a method', function () {
                $sig = new Signature(Signature::SHA1);
                $encrypted = $sig->calculate('this is a test');
                $this->assertEquals(
                    '+ia+Gd5r/5P3C8IwhDTkpEC7rQI=',
                    base64_encode($encrypted)
                );
            });
            $this->should('accept sha256 as a method', function () {
                $sig = new Signature(Signature::SHA256);
                $encrypted = $sig->calculate('this is a test');
                $this->assertEquals(
                    'Lpl1hUiXKo6IIq1H+hAX/3Lwbz/2oBaFH0XDmHMrxQw=',
                    base64_encode($encrypted)
                );
            });
            $this->should('accept sha512 as a method', function () {
                $sig = new Signature(Signature::SHA512);
                $encrypted = $sig->calculate('this is a test');
                $this->assertEquals(
                    'fQqEaO0iBADAuObzNbqn4HDOiAo34qxZlbmpe4CQJt5ibaY2rHNlJJu5dMcZ7fVDtS7ShmRvQ33H+BDMIGg3XA==',
                    base64_encode($encrypted)
                );
            });
            $this->should('accept ripemd160', function () {
                $sig = new Signature(Signature::RIPEMD160);
                $encrypted = $sig->calculate('this is a test');
                $this->assertEquals(
                    'VzZdtt3guPQhQxT6CbWHuvGzOfg=',
                    base64_encode($encrypted)
                );
            });
            $this->should('throw an Exception if an unknown method is given', function () {
                $this->expectException(Exception::class);
                $this->expectExceptionMessage('Invalid signature method given: ripemd256');
                $sig = new Signature('ripemd256');
                $encrypted = $sig->calculate('this is a test');
            });
        });
    }
}
