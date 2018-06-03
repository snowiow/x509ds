<?php

namespace X509DS\Tests;

use Codeception\Specify;
use DOMDocument;
use PHPUnit\Framework\TestCase;
use X509DS\Canonization;
use X509DS\Exceptions\AlgorithmException;

class CanonizationTest extends TestCase
{
    use Specify;

    private const RAW_FILE                          = __DIR__ . '/resources/raw.xml';
    private const C14N_FILE                         = __DIR__ . '/resources/c14n.xml';
    private const C14N_EXCLUSIVE_FILE               = __DIR__ . '/resources/c14n_exclusive.xml';
    private const C14N_WITH_COMMENTS_FILE           = __DIR__ . '/resources/c14n_with_comments.xml';
    private const C14N_WITH_COMMENTS_EXCLUSIVE_FILE = __DIR__ . '/resources/c14n_with_comments_exclusive.xml';

    public function testC14N()
    {
        $this->describe('Canonization', function () {
            $this->should('canonize via c14n', function () {
                $document = new DOMDocument();
                $document->load(self::RAW_FILE);
                $node = $document->getElementsByTagName('c')->item(0);
                $canonization = new Canonization(Canonization::C14N);
                $actual = $canonization->C14N($node);
                $this->assertXmlStringEqualsXmlFile(
                    self::C14N_FILE,
                    $actual
                );
            });
            $this->should('canonize via c14n exclusive', function () {
                $document = new DOMDocument();
                $document->load(self::RAW_FILE);
                $node = $document->getElementsByTagName('c')->item(0);
                $canonization = new Canonization(Canonization::C14N_EXCLUSIVE);
                $actual = $canonization->C14N($node);
                $this->assertXmlStringEqualsXmlFile(
                    self::C14N_EXCLUSIVE_FILE,
                    $actual
                );
            });
            $this->should('canonize via c14n with comments', function () {
                $document = new DOMDocument();
                $document->load(self::RAW_FILE);
                $node = $document->getElementsByTagName('c')->item(0);
                $canonization = new Canonization(Canonization::C14N_WITH_COMMENTS);
                $actual = $canonization->C14N($node);
                $this->assertXmlStringEqualsXmlFile(
                    self::C14N_WITH_COMMENTS_FILE,
                    $actual
                );
            });
            $this->should('canonize via c14n exclusive with comments', function () {
                $document = new DOMDocument();
                $document->load(self::RAW_FILE);
                $node = $document->getElementsByTagName('c')->item(0);
                $canonization = new Canonization(Canonization::C14N_WITH_COMMENTS_EXCLUSIVE);
                $actual = $canonization->C14N($node);
                $this->assertXmlStringEqualsXmlFile(
                    self::C14N_WITH_COMMENTS_EXCLUSIVE_FILE,
                    $actual
                );
            });
            $this->should('throw a AlgorithmException if an unknown method is given', function () {
                $this->expectException(AlgorithmException::class);
                $canonization = new Canonization('unknowncanonization');
            });
        });
    }
}
