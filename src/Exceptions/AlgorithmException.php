<?php

namespace X509DS\Exceptions;

use Exception;

/**
 * Class AlgorithmException
 *
 * @package X509DS\Exceptions
 */
final class AlgorithmException extends Exception
{
    public function __construct(string $invalidMethod, array $validMethods)
    {
        parent::__construct(
            sprintf(
                'Could not set method: %s' . PHP_EOL .
                'Must be one of: %s',
                $invalidMethod,
                implode(', ', $validMethods)
            )
        );
    }
}
