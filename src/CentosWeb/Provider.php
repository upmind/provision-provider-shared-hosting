<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\CentosWeb;

use GuzzleHttp\Client;
use Carbon\Carbon;
use Throwable;
use Upmind\ProvisionBase\Exception\ProvisionFunctionError;
use Upmind\ProvisionBase\Provider\Contract\ProviderInterface;
use Upmind\ProvisionBase\Provider\DataSet\AboutData;
use Upmind\ProvisionProviders\SharedHosting\Category;
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
use Upmind\ProvisionProviders\SharedHosting\CentosWeb\Data\Configuration;

/**
 * CentosWeb provision provider.
 */
class Provider extends Category implements ProviderInterface
{
    protected const MAX_USERNAME_LENGTH = 8;

    /**
     * @var Configuration
     */
    protected $configuration;

    /**
     * @var Api|null
     */
    protected $api;

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
            ->setName('CentosWeb')
            ->setDescription('Create and manage CentosWeb accounts and resellers using the CentosWeb API')
            ->setLogoUrl('https://api.upmind.io/images/logos/provision/centosweb-logo.png');
    }

    /**
     * @inheritDoc
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function create(CreateParams $params): AccountInfo
    {
        $asReseller = boolval($params->as_reseller ?? false);

        if (!$params->domain) {
            $this->errorResult('Domain name is required');
        }

        $username = $params->username ?: $this->generateUsername($params->domain);

        $this->api()->createAccount(
            $params,
            $username,
            $asReseller
        );

        return $this->_getInfo($username, $asReseller, 'Account created');
    }

    protected function generateUsername(string $base): string
    {
        return substr(
            preg_replace('/^[^a-z]+/', '', preg_replace('/[^a-z0-9]/', '', strtolower($base))),
            0,
            self::MAX_USERNAME_LENGTH
        ) . rand(0, 99);
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    protected function _getInfo(string $username, bool $isReseller, string $message): AccountInfo
    {
        $info = $this->api()->getAccountData($username, $isReseller);

        return AccountInfo::create($info)->setMessage($message);
    }

    /**
     * @inheritDoc
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function getInfo(AccountUsername $params): AccountInfo
    {
        $asReseller = boolval($params->is_reseller ?? false);

        return $this->_getInfo(
            $params->username,
            $asReseller,
            'Account info retrieved',
        );
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function getUsage(AccountUsername $params): AccountUsage
    {
        $asReseller = boolval($params->is_reseller ?? false);

        $usage = $this->api()->getAccountUsage($params->username, $asReseller);

        return AccountUsage::create()
            ->setUsageData($usage);
    }

    /**
     * @inheritDoc
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function getLoginUrl(GetLoginUrlParams $params): LoginUrl
    {
        $timer = 30;
        $loginUrl = $this->api()->getLoginUrl($params->username, $timer);

        return LoginUrl::create()
            ->setLoginUrl($loginUrl)
            ->setExpires(Carbon::now()->addMinutes($timer));
    }

    /**
     * @inheritDoc
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function changePassword(ChangePasswordParams $params): EmptyResult
    {
        $this->api()->updatePassword($params->username, $params->password);

        return $this->emptyResult('Password changed');
    }

    /**
     * @inheritDoc
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function changePackage(ChangePackageParams $params): AccountInfo
    {
        $this->api()->updatePackage($params->username, $params->package_name);

        return $this->_getInfo(
            $params->username,
            false,
            'Package changed'
        );
    }

    /**
     * @inheritDoc
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function suspend(SuspendParams $params): AccountInfo
    {
        $this->api()->suspendAccount($params->username);

        return $this->_getInfo($params->username, false, 'Account suspended');
    }

    /**
     * @inheritDoc
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function unSuspend(AccountUsername $params): AccountInfo
    {
        $this->api()->unsuspendAccount($params->username);

        return $this->_getInfo($params->username, false, 'Account unsuspended');
    }

    /**
     * @inheritDoc
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function terminate(AccountUsername $params): EmptyResult
    {
        $this->api()->deleteAccount($params->username);

        return $this->emptyResult('Account deleted');
    }

    /**
     * @inheritDoc
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function grantReseller(GrantResellerParams $params): ResellerPrivileges
    {
        $this->errorResult('Operation not supported');
    }

    /**
     * @inheritDoc
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function revokeReseller(AccountUsername $params): ResellerPrivileges
    {
        $this->errorResult('Operation not supported');
    }

    /**
     * @return no-return
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    protected function handleException(Throwable $e): void
    {
        // let the provision system handle this
        throw $e;
    }

    protected function api(): Api
    {
        if ($this->api) {
            return $this->api;
        }

        $client = new Client([
            'base_uri' => sprintf('https://%s:%s', $this->configuration->hostname, 2304),
            'headers' => [
                'Accept' => 'application/json',
            ],
            'connect_timeout' => 10,
            'timeout' => 60,
            'http_errors' => true,
            'allow_redirects' => false,
            'handler' => $this->getGuzzleHandlerStack(),
        ]);

        return $this->api = new Api($client, $this->configuration);
    }
}
