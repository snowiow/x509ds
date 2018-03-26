<?php

namespace X509DS;

/**
 * Class AlgorithmInterface
 *
 * @package X509DS
 */
interface AlgorithmInterface
{
    /**
     * @param string $method
     */
    public function setMethod(string $method): void;

    /**
     * @return string
     */
    public function getMethod(): string;
}
