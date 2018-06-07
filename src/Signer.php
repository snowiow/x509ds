<?php

namespace X509DS;

use DOMDocument;
use X509DS\Exception\InvalidPfxException;

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
    private $tags = [];

    /**
     * @var string
     */
    private $reference;

    /**
     * @var Canonization
     */
    private $canonization;

    /**
     * @var Digest
     */
    private $digestMethod;

    /**
     * @var Signature
     */
    private $signatureMethod;

    /**
     * @var string
     */
    private $target;

    /**
     * @var Certificate
     */
    private $certificate;

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
        //If PFX is the content it could contain a null byte and file_exists
        //would throw a warning, so it needs to be checked first.
        if (strpos($pfx, "\0") === false && file_exists($pfx)) {
            $pfxContent = file_get_contents($pfx);
        }
        $result = openssl_pkcs12_read($pfxContent, $certs, $password);
        if ($result === false) {
            throw new InvalidPfxException();
        }

        $signer = self::fromPrivateKey($certs['pkey']);
        $signer->setCertificate($certs['cert']);

        return $signer;
    }

    /**
     * Construct a Signer from a PrivateKey
     *
     * @param PrivateKey $pkey
     */
    private function __construct(PrivateKey $pkey)
    {
        $this->privateKey      = $pkey;
        $this->canonization    = new Canonization(Canonization::C14N);
        $this->digestMethod    = new Digest(Digest::SHA1);
        $this->signatureMethod = new Signature(Signature::SHA1);
        $this->target          = 'Header';
    }

    /**
     * @param string $method
     */
    public function setCanonization(string $method): void
    {
        $this->canonization->setMethod($method);
    }

    /**
     * @return string
     */
    public function getCanonization(): string
    {
        return $this->canonization->getMethod();
    }

    /**
     * @param string $method
     */
    public function setDigestMethod(string $method): void
    {
        $this->digestMethod->setMethod($method);
    }

    /**
     * @return string
     */
    public function getDigestMethod(): string
    {
        return $this->digestMethod->getMethod();
    }

    /**
     * @param string $method
     */
    public function setSignatureMethod(string $method): void
    {
        $this->signatureMethod->setMethod($method);
    }

    /**
     * @return string
     */
    public function getSignatureMethod(): string
    {
        return $this->signatureMethod->getMethod();
    }

    /**
     * @param string $target
     */
    public function setTarget(string $target): void
    {
        $this->target = $target;
    }

    /**
     * @param string $uri
     */
    public function setSecurityTokenReference(string $uri): void
    {
        $this->reference = $uri;
    }

    /**
     * @param string $certificate
     */
    public function setCertificate(string $certificate)
    {
        $this->certificate = new Certificate($certificate);
    }

    /**
     * @return Certificate
     */
    public function getCertificate(): Certificate
    {
        return $this->certificate;
    }

    /**
     * @param array $tags
     */
    public function setTags(array $tags): void
    {
        $this->tags = $tags;
    }

    /**
     * Sign the given document
     *
     * @param string|DOMDocument $doc Can be an XML Content string, the path or
     *                                an DOMDocument object
     *
     * @return DOMDocument the signed document
     */
    public function sign($doc): DOMDocument
    {
        $dom                  = DOMReader::read($doc);
        $signatureNodeFactory = new SignatureNodeFactory(
            $this->canonization->getMethod(),
            $this->signatureMethod->getMethod(),
            $this->digestMethod->getMethod(),
            $dom
        );

        $digestValues = [];
        foreach ($this->tags as $tag => $uri) {
            $node                   = $dom->getElementsByTagName($tag)->item(0);
            $canonized              = $this->canonization->C14N($node);
            $digestValues[$uri]     = base64_encode($this->digestMethod->calculate($canonized));
        }
        $signedInfoNode    = $signatureNodeFactory->createSignatureNode($this->target, $digestValues);
        $canonized         = $this->canonization->C14N($signedInfoNode);
        $signature         = $this->signatureMethod->calculate($canonized, $this->privateKey);
        $signatureNodeFactory->appendSignatureValueNode('Signature', $signature);

        if ($this->reference !== null) {
            $signatureNodeFactory->appendSecurityTokenReference('Signature', $this->reference);
        }

        return $dom;
    }
}
