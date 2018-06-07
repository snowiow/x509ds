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

    /**
     * @param string $certificate the certificates content, which will be
     *                            wrapped by this class
     */
    public function __construct(string $certificate)
    {
        $this->certificateString = $certificate;
    }

    /**
     * Returns the string content of the certificate
     *
     * @return string
     */
    public function getString(): string
    {
        return $this->certificateString;
    }
}
