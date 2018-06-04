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
     * Sets the method with which the algorithm is working
     *
     * @param string $method
     */
    public function setMethod(string $method): void;

    /**
     * @return string
     */
    public function getMethod(): string;

    /**
     * Return a list of all valid methods, with which the algorithm can work
     *
     * @return array
     */
    public function getMethods(): array;
}
