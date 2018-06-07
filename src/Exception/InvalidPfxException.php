<?php

namespace X509DS\Exception;

use Exception;

/**
 * Class InvalidPfxException
 *
 * @package X509\Exception
 */
final class InvalidPfxException extends Exception
{
    public function __construct()
    {
        parent::__construct('Could not parse pfx');
    }
}
