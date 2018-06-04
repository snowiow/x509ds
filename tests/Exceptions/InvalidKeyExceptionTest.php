<?php

namespace X509DS\Tests\Exception;

use PHPUnit\Framework\TestCase;
use X509DS\Exception\InvalidKeyException;

class InvalidKeyExceptionTest extends TestCase
{
    public function testException()
    {
        $this->expectException(InvalidKeyException::class);
        $this->expectExceptionMessage('Could not parse key');

        throw new InvalidKeyException();
    }
}
