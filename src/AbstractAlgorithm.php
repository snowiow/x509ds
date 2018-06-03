<?php

namespace X509DS;

use X509DS\Exceptions\AlgorithmException;

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
     * @param string $method
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

    abstract public function getMethods(): array;
}
