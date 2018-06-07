<?php

namespace X509DS;

use DOMNode;
use Exception;

/**
 * Class Canonization
 *
 * @package X509DS
 */
final class Canonization extends AbstractAlgorithm
{
    public const C14N                         = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
    public const C14N_EXCLUSIVE               = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    public const C14N_WITH_COMMENTS           = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';
    public const C14N_WITH_COMMENTS_EXCLUSIVE = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';

    /**
     * @param string $method Canonization will be initialized with the given
     *                       method
     */
    public function __construct(string $method = self::C14N)
    {
        $this->setMethod($method);
    }

    /**
     * Canonize the given node
     *
     * @oaram DOMNode $node the node, which will be canonized
     *
     * @return string the canonized string
     */
    public function C14N(DOMNode $node): string
    {
        switch ($this->method) {
        case self::C14N:
            return $node->C14N(false, false);
        case self::C14N_WITH_COMMENTS:
            return $node->C14N(false, true);
        case self::C14N_EXCLUSIVE:
            return $node->C14N(true, false);
        case self::C14N_WITH_COMMENTS_EXCLUSIVE:
            return $node->C14N(true, true);
        }
        throw new Exception('Invalid canonization method given: ' . $this->method);
    }

    /**
     * Return a list of all valid methods, with which the algorithm can work
     *
     * @return array
     */
    public function getMethods(): array
    {
        return [
            self::C14N,
            self::C14N_EXCLUSIVE,
            self::C14N_WITH_COMMENTS,
            self::C14N_WITH_COMMENTS_EXCLUSIVE,
        ];
    }
}
