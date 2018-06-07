<?php

namespace X509DS\Exception;

use Exception;

/**
 * Class InvalidKeyException
 *
 * @package X509\Exception
 */
final class InvalidKeyException extends Exception
{
    public function __construct()
    {
        parent::__construct('Could not parse key');
    }
}
