<?php

namespace X509DS;

/**
 * Class AbstractAlgorith
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
        $this->method = $method;
    }

    /**
     * @return string
     */
    public function getMethod(): string
    {
        return $this->method;
    }
}
