<?php

namespace X509DS\Exceptions;

use Exception;

/**
 * Class InvalidXmlException
 *
 * @package X509DS\Exceptions
 */
final class InvalidXmlException extends Exception
{
    public function __construct(string $content)
    {
        parent::__construct('Invalid XML given: ' . $content);
    }
}
