<?php

namespace X509DS\Exceptions;

use PHPUnit\Framework\TestCase;

class AlgorithmExceptionTest extends TestCase
{
    public function testException()
    {
        $this->expectException(AlgorithmException::class);
        $this->expectExceptionMessage(
            'Could not set method: a' . PHP_EOL .
            'Must be one of: b, c, d'
        );
        throw new AlgorithmException('a', ['b', 'c', 'd']);
    }
}
