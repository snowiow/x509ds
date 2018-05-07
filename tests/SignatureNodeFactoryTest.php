<?php

namespace X509DS\Tests;

use PHPUnit\Framework\TestCase;
use X509DS\Canonization;
use X509DS\Signature;
use X509DS\SignatureNodeFactory;

class SignatureNodeFactoryTest extends TestCase
{
    /**
     * @var SignatureNodeFactory
     */
    private $signatureNodeFactory;

    public function setUp()
    {
        $this->signatureNodeFactory = new SignatureNodeFactory(Canonization::C14N_EXCLUSIVE, Signature::SHA1);
    }

    public function testCreateSignatureMethodNode()
    {
        $node       = $this->signatureNodeFactory->createSignatureMethodNode();
        $doc        = $this->signatureNodeFactory->getDocument();
        $doc->appendChild($node);
        $pos        = strpos(
            $doc->saveXML(),
            '<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>'
        );
        $this->assertTrue($pos > 0);
    }

    public function testCreateCanonizationMethodNode()
    {
        $node       = $this->signatureNodeFactory->createCanonicalizationMethodNode();
        $doc        = $this->signatureNodeFactory->getDocument();
        $doc->appendChild($node);
        $pos        = strpos(
            $doc->saveXML(),
            '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
        );
        $this->assertTrue($pos > 0);
    }

    public function testCreateReferenceNode()
    {
        $node = $this->signatureNodeFactory->createReferenceNode(
            '#test',
            'testvalue'
        );
        $doc = $this->signatureNodeFactory->getDocument();
        $doc->appendChild($node);
        $pos = strpos(
            $doc->saveXML(),
            '<ds:Reference URI="#test"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>testvalue</ds:DigestValue></ds:Reference>'
        );
        $this->assertTrue($pos > 0);
    }

    public function testAppendSecurityTokenReference()
    {
        $node = $this->signatureNodeFactory->createSignatureMethodNode();
        $doc  = $this->signatureNodeFactory->getDocument();
        $doc->appendChild($node);
        $this->signatureNodeFactory->appendSecurityTokenReference('ds:SignatureMethod', '#test');
        $pos = strpos(
            $doc->saveXml(),
            '<ds:KeyInfo><wsse:SecurityTokenReference><wsse:Reference URI="#test"/></wsse:SecurityTokenReference></ds:KeyInfo>'
        );
        $this->assertTrue($pos > 0);
    }
}
