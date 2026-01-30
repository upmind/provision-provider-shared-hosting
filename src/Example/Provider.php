<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\Example;

use GuzzleHttp\Client;
use Upmind\ProvisionBase\Provider\Contract\ProviderInterface;
use Upmind\ProvisionBase\Provider\DataSet\AboutData;
use Upmind\ProvisionProviders\SharedHosting\Category;
use Upmind\ProvisionProviders\SharedHosting\Data\ChangePrimaryDomainParams;
use Upmind\ProvisionProviders\SharedHosting\Data\CreateParams;
use Upmind\ProvisionProviders\SharedHosting\Data\AccountInfo;
use Upmind\ProvisionProviders\SharedHosting\Data\AccountUsage;
use Upmind\ProvisionProviders\SharedHosting\Data\AccountUsername;
use Upmind\ProvisionProviders\SharedHosting\Data\ChangePackageParams;
use Upmind\ProvisionProviders\SharedHosting\Data\ChangePasswordParams;
use Upmind\ProvisionProviders\SharedHosting\Data\EmptyResult;
use Upmind\ProvisionProviders\SharedHosting\Data\GetLoginUrlParams;
use Upmind\ProvisionProviders\SharedHosting\Data\GrantResellerParams;
use Upmind\ProvisionProviders\SharedHosting\Data\LoginUrl;
use Upmind\ProvisionProviders\SharedHosting\Data\ResellerPrivileges;
use Upmind\ProvisionProviders\SharedHosting\Data\SuspendParams;
use Upmind\ProvisionProviders\SharedHosting\Example\Data\Configuration;

/**
 * Example hosting provider template.
 */
class Provider extends Category implements ProviderInterface
{
    protected Configuration $configuration;
    protected Client $client;

    public function __construct(Configuration $configuration)
    {
        $this->configuration = $configuration;
    }

    /**
     * @inheritDoc
     */
    public static function aboutProvider(): AboutData
    {
        return AboutData::create()
            ->setName('Example Provider')
            ->setDescription('Empty provider for demonstration purposes');
    }

    /**
     * @inheritDoc
     */
    public function create(CreateParams $params): AccountInfo
    {
        throw $this->errorResult('Not implemented');
    }

    /**
     * @inheritDoc
     */
    public function getInfo(AccountUsername $params): AccountInfo
    {
        // $accountInfo = $this->client()->get(sprintf('accounts/%s', $username));

        return AccountInfo::create()
            ->setDomain($params->domain)
            ->setUsername($params->username)
            ->setServerHostname($this->configuration->hostname)
            ->setPackageName('Example Hosting')
            ->setReseller(false)
            ->setSuspended(false);
    }

    public function getUsage(AccountUsername $params): AccountUsage
    {
        throw $this->errorResult('Not implemented');
    }

    /**
     * @inheritDoc
     */
    public function getLoginUrl(GetLoginUrlParams $params): LoginUrl
    {
        throw $this->errorResult('Not implemented');
    }

    /**
     * @inheritDoc
     */
    public function changePassword(ChangePasswordParams $params): EmptyResult
    {
        throw $this->errorResult('Not implemented');
    }

    /**
     * @inheritDoc
     */
    public function changePackage(ChangePackageParams $params): AccountInfo
    {
        throw $this->errorResult('Not implemented');
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function changePrimaryDomain(ChangePrimaryDomainParams $params): AccountInfo
    {
        $this->errorResult('Not implemented');
    }

    /**
     * @inheritDoc
     */
    public function suspend(SuspendParams $params): AccountInfo
    {
        throw $this->errorResult('Not implemented');
    }

    /**
     * @inheritDoc
     */
    public function unSuspend(AccountUsername $params): AccountInfo
    {
        throw $this->errorResult('Not implemented');
    }

    /**
     * @inheritDoc
     */
    public function terminate(AccountUsername $params): EmptyResult
    {
        throw $this->errorResult('Not implemented');
    }

    /**
     * @inheritDoc
     */
    public function grantReseller(GrantResellerParams $params): ResellerPrivileges
    {
        throw $this->errorResult('Not implemented');
    }

    /**
     * @inheritDoc
     */
    public function revokeReseller(AccountUsername $params): ResellerPrivileges
    {
        throw $this->errorResult('Not implemented');
    }

    /**
     * Get a Guzzle HTTP client instance.
     */
    protected function client(): Client
    {
        return $this->client ??= new Client([
            'handler' => $this->getGuzzleHandlerStack(boolval($this->configuration->debug)),
            'base_uri' => sprintf('https://%s/v1/', $this->configuration->hostname),
            'headers' => [
                'Authorization' => 'Bearer ' . $this->configuration->api_token,
            ],
        ]);
    }
}
