<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\PleskOnyxRPC\Api;

use PleskX\Api\Client as PleskClient;
use PleskX\Api\XmlResponse;
use Psr\Log\LoggerInterface;
use SimpleXMLElement;

class Client extends PleskClient
{
    protected LoggerInterface $logger;

    /**
     * Pass a logger implementation to enable debug logging.
     */
    public function setLogger(?LoggerInterface $logger): void
    {
        $this->logger = $logger;
    }

    /**
     * @inheritDoc
     */
    public function request($request, $mode = self::RESPONSE_SHORT)
    {
        if ($request instanceof SimpleXMLElement) {
            $request = $request->asXml();
        } else {
            $xml = $this->getPacket();

            if (is_array($request)) {
                $request = $this->_arrayToXml($request, $xml)->asXML();
            } elseif (preg_match('/^[a-z]/', $request)) {
                $request = $this->_expandRequestShortSyntax($request, $xml);
            }
        }

        $request = (string)$request;

        if (isset($this->logger)) {
            $this->logger->debug("Plesk API request:\n" . $request);
        }

        return parent::request(new SimpleXMLElement($request), $mode);
    }

    /**
     * @inheritDoc
     *
     * @param XmlResponse|string|mixed $xml
     */
    protected function _verifyResponse($xml)
    {
        if (isset($this->logger)) {
            $xmlString = $xml instanceof XmlResponse ? $xml->asXML() : (string)$xml;
            $this->logger->debug("Plesk API response:\n" . $xmlString);
        }

        parent::_verifyResponse($xml);
    }
}
