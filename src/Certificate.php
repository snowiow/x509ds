<?php

namespace X509DS;

/**
 * Class Certificate
 *
 * @package X509DS
 */
final class Certificate
{
    /**
     * @var string
     */
    private $certificateString;

    public function __construct(string $certificate)
    {
        $this->certificateString = $certificate;
    }

    /**
     * @return string
     */
    public function getString(): string
    {
        return $this->certificateString;
    }
}
