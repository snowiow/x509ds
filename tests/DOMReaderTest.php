<?php

namespace X509DS\Tests;

use Codeception\Specify;
use DOMDocument;
use PHPUnit\Framework\TestCase;
use X509DS\DOMReader;
use X509DS\Exception\InvalidXmlException;

class DOMReaderTest extends TestCase
{
    use Specify;

    private const XML          = __DIR__ . '/resources/request.xml';
    private const INVALID_XML  = __DIR__ . '/resources/invalid_xml.xml';

    public function testRead()
    {
        $this->describe('DOMReader', function () {
            $this->should('read the document from a DOMDocument', function () {
                $document = new DOMDocument();
                $document->load(self::XML);
                $dom = DOMReader::read($document);
                $this->assertInstanceOf(DOMDocument::class, $dom);
            });
            $this->should('read the document from a XML string', function () {
                $document = new DOMDocument();
                $document->loadXml(file_get_contents(self::XML));
                $dom = DOMReader::read($document);
                $this->assertInstanceOf(DOMDocument::class, $dom);
            });
            $this->should('read the document from a path', function () {
                $dom = DOMReader::read(self::XML);
                $this->assertInstanceOf(DOMDocument::class, $dom);
            });
        });
    }

    public function testReadInvalidXmlString()
    {
        $this->expectException(InvalidXmlException::class);
        $this->expectExceptionMessage('Invalid XML given: no valid xml');
        $dom = DOMReader::read('no valid xml');
        $this->assertInstanceOf(DOMDocument::class, $dom);
    }

    public function testReadInvalidXmlPathContent()
    {
        $this->expectException(InvalidXmlException::class);
        $this->expectExceptionMessage('Invalid XML given: this is no xml');
        $dom = DOMReader::read(self::INVALID_XML);
        $this->assertInstanceOf(DOMDocument::class, $dom);
    }
}
