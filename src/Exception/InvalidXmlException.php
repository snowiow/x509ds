<?php

namespace X509DS\Exception;

use Exception;

/**
 * Class InvalidXmlException
 *
 * @package X509DS\Exception
 */
final class InvalidXmlException extends Exception
{
    public function __construct(string $content)
    {
        parent::__construct('Invalid XML given: ' . $content);
    }
}
