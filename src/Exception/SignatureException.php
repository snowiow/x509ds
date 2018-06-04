<?php

namespace X509DS\Exception;

use Exception;

/**
 * Class SignatureException
 *
 * @package X509DS\Exception
 */
final class SignatureException extends Exception
{
    public function __construct()
    {
        parent::__construct('Could not sign content');
    }
}
