<?php

namespace X509DS\Exception;

use Exception;

/**
 * Class FileNotFoundException
 *
 * @package X509DS\Exception
 */
final class FileNotFoundException extends Exception
{
    /**
     * @param string $path the path, which doesn't exist in file system
     */
    public function __construct(string $path)
    {
        parent::__construct('File not found: ' . $path);
    }
}
