<?php

namespace X509DS\Tests\Exceptions;

use PHPUnit\Framework\TestCase;
use X509DS\Exceptions\InvalidKeyException;

class InvalidKeyExceptionTest extends TestCase
{
    public function testException()
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Could not parse key');

        throw new InvalidKeyException();
    }
}
