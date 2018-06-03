<?php

namespace X509DS\Exceptions;

use Exception;

/**
 * Class SignatureException
 *
 * @package X509DS\Exceptions
 */
final class SignatureException extends Exception
{
    public function __construct()
    {
        parent::__construct('Could not sign content');
    }
}
