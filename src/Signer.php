<?php

namespace X509DS;

use DOMDocument;

/**
 * Class Signer
 *
 * @package Xml509Ds
 */
final class Signer
{
    /**
     * @var PrivateKey
     */
    private $privateKey;

    /**
     * @var array
     */
    private $tags;

    /**
     * @var Canonization
     */
    private $canonization;

    /**
     * @var Signature
     */
    private $signature;

    /**
     * @var string
     */
    private $target;

    /**
     * @var SignatureNodeFactory
     */
    private $signatureNodeFactory;

    /**
     * Create a Signer from the given Private Key
     *
     * @param string|resource $pkey Can be a the content of the private key, a
     *                              path or the openssl resource
     *
     * @return Signer
     */
    public static function fromPrivateKey($pkey, string $password = ''): self
    {
        if (!is_string($pkey)) {
            return new self(PrivateKey::fromResource($pkey));
        }
        if (file_exists($pkey)) {
            return new self(PrivateKey::fromPath($pkey, $password));
        }

        return new self(PrivateKey::fromContent($pkey, $password));
    }

    /**
     * Construct a Signer from a PrivateKey
     *
     * @param PrivateKey $pkey
     */
    private function __construct(PrivateKey $pkey)
    {
        $this->privateKey   = $pkey;
        $this->canonization = new Canonization(Canonization::C14N);
        $this->signature    = new Signature(Signature::SHA1);
    }

    /**
     * @param string $method
     */
    public function setCanonization(string $method): void
    {
        $this->canonization->setMethod($method);
    }

    public function setTarget(string $target): void
    {
        $this->target = $target;
    }

    /**
     * Set a Document to be signed
     *
     * @param string|DOMDocument $doc Can be an XML Content string, the path or
     *                                an DOMDocument object
     */
    public function setDocument($doc): void
    {
        $document = null;
        if (!is_string($doc)) {
            $document = $doc;
        } elseif (is_file($doc)) {
            $document = DOMDocument::load($doc);
        } else {
            $document = DOMDocument::loadXML($doc);
        }
        $this->signatureNodeFactory = new SignatureNodeFactory(
            $this->canonization->getMethod(),
            $this->signature->getMethod(),
            $document
        );
    }

    /**
     * @return DOMDocument
     */
    public function getDocument(): DOMDocument
    {
        return $this->signatureNodeFactory->getDocument();
    }

    public function setTags(array $tags): void
    {
        $this->tags = $tags;
    }

    public function sign(): DOMDocument
    {
        $document     = $this->signatureNodeFactory->getDocument();
        $digestValues = [];
        foreach ($this->tags as $tag => $uri) {
            $node               = $document->getElementsByTagName($tag)->item(0);
            $canonized          = $this->canonization->C14N($node);
            $digestValues[$uri] = base64_encode($this->signature->calculate($canonized));
        }
        $signedInfoNode = $this->signatureNodeFactory->createSignatureNode($this->target, $digestValues);
        $canonized      = $this->canonization->C14N($signedInfoNode);
        $signature      = $this->privateKey->sign($canonized);
        $this->signatureNodeFactory->appendSignatureValueNode('Signature', base64_encode($signature));

        return $this->signatureNodeFactory->getDocument();
    }
}
