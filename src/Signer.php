<?php

namespace X509DS;

use DOMDocument;
use X509DS\Exceptions\InvalidPfxException;

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
     * @var DOMDocument
     */
    private $document;

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
     * Create a Signer from the given Pfx File
     *
     * @param string $pfx      path or content of the pfx file
     * @param string $password the password for securing the pfx
     *
     * @throw InvalidPfxException will be thrown if openssl can't read the pfx
     *
     * @return Signer
     */
    public static function fromPfx(string $pfx, string $password): self
    {
        $pfxContent = $pfx;
        if (file_exists($pfx)) {
            $pfxContent = file_get_contents($pfx);
        }
        $result = openssl_pkcs12_read($pfxContent, $certs, $password);
        if ($result === false) {
            throw new InvalidPfxException();
        }

        return self::fromPrivateKey($certs['pkey']);
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
        if (!is_string($doc)) {
            $this->document = $doc;
        } else {
            $this->document = new DOMDocument();
            if (is_file($doc)) {
                $this->document->load($doc);
            } else {
                $this->document->loadXML($doc);
            }
        }
    }

    /**
     * @return DOMDocument
     */
    public function getDocument(): DOMDocument
    {
        return $this->document;
    }

    public function setTags(array $tags): void
    {
        $this->tags = $tags;
    }

    public function sign(): DOMDocument
    {
        $signatureNodeFactory = new SignatureNodeFactory(
            $this->canonization->getMethod(),
            $this->signature->getMethod(),
            $this->document
        );

        $digestValues = [];
        foreach ($this->tags as $tag => $uri) {
            $node                   = $this->document->getElementsByTagName($tag)->item(0);
            $canonized              = $this->canonization->C14N($node);
            $digestValues[$uri]     = base64_encode($this->signature->calculate($canonized));
        }
        $signedInfoNode = $signatureNodeFactory->createSignatureNode($this->target, $digestValues);
        $canonized      = $this->canonization->C14N($signedInfoNode);
        $signature      = $this->privateKey->sign($canonized);
        $signatureNodeFactory->appendSignatureValueNode('Signature', base64_encode($signature));

        return $this->document;
    }
}
