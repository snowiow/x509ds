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
    const C14N                         = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
    const C14N_EXCLUSIVE               = 'http://www.w3.org/2001/10/xml-exc-c14n#';
    const C14N_WITH_COMMENTS           = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';
    const C14N_WITH_COMMENTS_EXCLUSIVE = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';

    public function __construct(string $method = self::C14N)
    {
        $this->method = $method;
    }

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
}
