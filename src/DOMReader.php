<?php

namespace X509DS;

use DOMDocument;
use X509DS\Exception\InvalidXmlException;

/**
 * Class DOMReader
 *
 * @package X509DS
 */
final class DOMReader
{
    /**
     * Reads the data and tries to load it into an DOMDocument
     *
     * @param string|DOMDocument $doc Can be an XML Content string, the path or
     *
     * @return DOMDocument
     */
    public static function read($doc): DOMDocument
    {
        if (!is_string($doc)) {
            return $doc;
        }
        libxml_use_internal_errors(true);
        $dom = new DOMDocument('1.0', 'utf-8');
        if (is_file($doc)) {
            $dom->load($doc);
            if (libxml_get_last_error()) {
                libxml_clear_errors();
                throw new InvalidXmlException(file_get_contents($doc));
            }
        } else {
            $dom->loadXML($doc);
            if (libxml_get_last_error()) {
                libxml_clear_errors();
                throw new InvalidXmlException($doc);
            }
        }

        return $dom;
    }
}
