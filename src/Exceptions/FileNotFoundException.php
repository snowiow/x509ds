<?php

namespace X509DS\Exceptions;

use Exception;

/**
 * Class FileNotFoundException
 *
 * @package X509DS\Exceptions
 */
final class FileNotFoundException extends Exception
{
    public function __construct($path)
    {
        parent::__construct('File not found: ' . $path);
    }
}
