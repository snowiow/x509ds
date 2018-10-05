<?php

namespace X509DS\Exceptions;

use Exception;

/**
 * Class InvalidKeyException
 *
 * @package X509\Exceptions
 */
final class InvalidKeyException extends Exception
{
    public function __construct()
    {
        parent::__construct('Could not parse key');
    }
}