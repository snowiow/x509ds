<?php

namespace X509DS;

use DOMDocument;
use DOMElement;
use DOMNode;

/**
 * Class DomNodeFactory
 *
 * @package X509DS
 */
final class SignatureNodeFactory
{
    /**
     * @var DOMDocument
     */
    private $document;

    /**
     * @var DOMNode
     */
    private $target;

    /**
     * @var string
     */
    private $digestMethod;

    /**
     * @var string
     */
    private $signatureMethod;

    /**
     * @var string
     */
    private $canonizationMethod;

    /**
     * Construct a SignatureNodeFactory with the given method strings. These
     * will be put as XML namespaces in the XML tags
     *
     * @param string      $canonization    the canonization method as a XML namespace
     * @param string      $signatureMethod the signature method as a XML namespace
     * @param string      $digestMethod    the digest method as a XML namespace
     * @param DOMDocument $document        the document on which the new nodes will be
     *                                     created
     */
    public function __construct(string $canonization, string $signatureMethod, string $digestMethod, DOMDocument $document = null)
    {
        if ($document === null) {
            $document = new DOMDocument('1.0', 'utf-8');
        }
        $this->document           = $document;
        $this->canonizationMethod = $canonization;
        $this->digestMethod       = $digestMethod;
        $this->signatureMethod    = $signatureMethod;
    }

    /**
     * @return DOMDocument the DOMDocument in it's current, modfified state
     */
    public function getDocument(): DOMDocument
    {
        return $this->document;
    }

    /**
     * Creates the signature node. This is the parent of every signature sub
     * node
     *
     * @param string $target     where to add the node as child. A node name is
     *                           expected and will be determined by getElementsByTagName
     * @param array  $references all the reference DOMNodes, which will be
     *                           appended to the SignatureNode as children
     *
     * @return DOMNode
     */
    public function createSignatureNode(string $target, array $references): DOMNode
    {
        $targetNode    = $this->document->getElementsByTagName($target)->item(0);
        $signatureNode = $this->document->createElementNS(
            'http://www.w3.org/2000/09/xmldsig#',
            'ds:Signature'
        );

        $signedInfoNode = $this->document->createElement('ds:SignedInfo');

        $canonizationNode = $this->createCanonicalizationMethodNode($this->canonizationMethod);
        $signedInfoNode->appendChild($canonizationNode);

        $digestMethodNode = $this->createSignatureMethodNode($this->signatureMethod);
        $signedInfoNode->appendChild($digestMethodNode);

        foreach ($references as $uri => $value) {
            $referenceNode = $this->createReferenceNode($uri, $value);
            $signedInfoNode->appendChild($referenceNode);
        }
        $signatureNode->appendChild($signedInfoNode);
        $targetNode->appendChild($signatureNode);

        // Otherwise the returned signedInfo C14N doesn't countain parent ns
        $xml = $this->document->saveXML();
        $this->document->loadXML($xml);

        return $this->document->getElementsByTagName('SignedInfo')->item(0);
    }

    /**
     * @return DOMNode
     */
    public function createSignatureMethodNode(): DOMNode
    {
        return $this->createNodeWithAlgorithm(
            'ds:SignatureMethod',
            $this->signatureMethod
        );
    }

    /**
     * @return DOMNode
     */
    public function createCanonicalizationMethodNode(): DOMNode
    {
        return $this->createNodeWithAlgorithm(
            'ds:CanonicalizationMethod',
            $this->canonizationMethod
        );
    }

    /**
     * Creates a reference node
     *
     * @param string $uri   the uri to the identifier, to which node this
     *                      reference node belongs
     * @param string $value the calculated value of the node, which will
     *                      be set as the digestValue
     *
     * @return DOMNode
     */
    public function createReferenceNode(string $uri, string $value): DOMNode
    {
        $referenceNode = $this->document->createElement('ds:Reference');
        $attr          = $referenceNode->setAttribute('URI', $uri);

        $transformsNode   = $this->document->createElement('ds:Transforms');
        $transformNode    = $this->document->createElement('ds:Transform');
        $this->createAlgorithmAttribute($transformNode, $this->canonizationMethod);
        $transformsNode->appendChild($transformNode);

        $digestMethodNode = $this->document->createElement('ds:DigestMethod');
        $digestAttr       = $this->createAlgorithmAttribute(
            $digestMethodNode,
            $this->digestMethod
        );

        $digestValueNode = $this->document->createElement('ds:DigestValue', $value);

        $referenceNode->appendChild($transformsNode);
        $referenceNode->appendChild($digestMethodNode);
        $referenceNode->appendChild($digestValueNode);

        return $referenceNode;
    }

    /**
     * Appends the signature value node to the signature node
     *
     * @param string $target the target at which the node will be appended
     *                       as a child
     * @param string $value  the calculated value to be set into the node
     */
    public function appendSignatureValueNode(string $target, string $value): void
    {
        $targetNode = $this->document->getElementsByTagName($target)->item(0);
        $node       = $this->document->createElement('ds:SignatureValue', $value);
        $targetNode->appendChild($node);
    }

    /**
     * Appends a optional SecurityTokenReference node to the Signature
     *
     * @param string $target the target at which the node will be appended
     *                       as a child
     * @param string $uri    the uri to the BinarySecurityToken identifier
     */
    public function appendSecurityTokenReference(string $target, string $uri): void
    {
        $targetNode    = $this->document->getElementsByTagName($target)->item(0);
        $node          = $this->document->createElement('ds:KeyInfo');
        $stcNode       = $this->document->createElement('wsse:SecurityTokenReference');
        $referenceNode = $this->document->createElement('wsse:Reference');
        $attr          = $referenceNode->setAttribute('URI', $uri);
        $stcNode->appendChild($referenceNode);
        $node->appendChild($stcNode);
        $targetNode->appendChild($node);
    }

    /**
     * Creates a Algorithm Node with the given name and method
     *
     * @param string $nodeName the name of the node
     * @params string $method the method which will be set as the nodes
     * attribute
     *
     * @return DOMNode
     */
    private function createNodeWithAlgorithm(string $nodeName, string $method): DOMNode
    {
        $node = $this->document->createElement($nodeName);
        $attr = $this->createAlgorithmAttribute($node, $method);

        return $node;
    }

    /**
     * Create the Algorithm Attribute
     *
     * @param DOMElement $elem The element to which the algo attribute is set
     * @param string     $algo the name of the algorithm, which will be the value
     *                         of the attribute
     */
    private function createAlgorithmAttribute(DOMElement $elem, string $algo): void
    {
        $elem->setAttribute('Algorithm', $algo);
    }
}
