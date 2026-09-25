<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\Tests\Unit\CyberPanel;

use Upmind\ProvisionProviders\SharedHosting\CyberPanel\Api;
use Upmind\ProvisionProviders\SharedHosting\CyberPanel\Data\Configuration;
use Upmind\ProvisionProviders\SharedHosting\CyberPanel\Provider;

/**
 * Provider with an injectable Api, and public access to its protected helpers.
 */
class TestableProvider extends Provider
{
    private Api $testApi;

    public function __construct(Configuration $configuration, Api $api)
    {
        parent::__construct($configuration);

        $this->testApi = $api;
    }

    protected function api(): Api
    {
        return $this->testApi;
    }

    public function publicControlPanelUrl(): string
    {
        return $this->controlPanelUrl();
    }

    public function publicGenerateUsername(string $base): string
    {
        return $this->generateUsername($base);
    }
}
