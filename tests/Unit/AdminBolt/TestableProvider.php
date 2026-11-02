<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\Tests\Unit\AdminBolt;

use GuzzleHttp\Client;
use Psr\Log\NullLogger;
use Upmind\ProvisionProviders\SharedHosting\AdminBolt\Data\Configuration;
use Upmind\ProvisionProviders\SharedHosting\AdminBolt\Provider;

/**
 * Provider with an injectable HTTP client, and access to the client it builds itself.
 */
class TestableProvider extends Provider
{
    private Client $testClient;

    public function __construct(Configuration $configuration, Client $client)
    {
        parent::__construct($configuration);

        $this->testClient = $client;
        $this->setLogger(new NullLogger());
    }

    protected function client(): Client
    {
        return $this->testClient;
    }

    public function realClient(): Client
    {
        return parent::client();
    }
}
