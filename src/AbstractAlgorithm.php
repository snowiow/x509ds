<?php

namespace X509DS;

use X509DS\Exception\AlgorithmException;

/**
 * Class AbstractAlgorithm
 *
 * @package X509DS
 */
abstract class AbstractAlgorithm implements AlgorithmInterface
{
    /**
     * @var string
     */
    protected $method;

    /**
     * Sets the method with which the algorithm is working
     *
     * @param string $method
     *
     * @throws AlgorithmException if a method will be set, which is not
     *                            supported by the algorithm
     */
    public function setMethod(string $method): void
    {
        if (!in_array($method, $this->getMethods())) {
            throw new AlgorithmException($method, $this->getMethods());
        }
        $this->method = $method;
    }

    /**
     * @return string
     */
    public function getMethod(): string
    {
        return $this->method;
    }

    /**
     * Return a list of all valid methods, with which the algorithm can work
     *
     * @return array
     */
    abstract public function getMethods(): array;
}
