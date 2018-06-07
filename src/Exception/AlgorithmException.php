<?php

namespace X509DS\Exception;

use Exception;

/**
 * Class AlgorithmException
 *
 * @package X509DS\Exception
 */
final class AlgorithmException extends Exception
{
    /**
     * @param string $invalidMethod the invalid method, which was given to the
     *                              algorithm
     * @param array  $validMethods  a list of valid methods, which will be printed
     *                              as well for reference
     */
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
