<?php

namespace X509DS\Exceptions;

use Exception;

/**
 * Class InvalidPfxException
 *
 * @package X509\Exceptions
 */
final class InvalidPfxException extends Exception
{
    public function __construct()
    {
        parent::__construct('Could not parse pfx');
    }
}
