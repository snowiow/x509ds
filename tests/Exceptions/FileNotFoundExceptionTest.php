<?php

namespace X509DS\Tests\Exceptions;

use PHPUnit\Framework\TestCase;
use X509DS\Exceptions\FileNotFoundException;

class FileNotFoundExceptionTest extends TestCase
{
    public function testException()
    {
        $path = '/var/www/pkey.key';

        $this->expectException(FileNotFoundException::class);
        $this->expectExceptionMessage('File not found: ' . $path);

        throw new FileNotFoundException($path);
    }
}
