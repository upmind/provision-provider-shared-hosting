<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\SPanel;

use GuzzleHttp\Exception\ClientException;
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
use Upmind\ProvisionProviders\SharedHosting\SPanel\Data\Configuration;

/**
 * SPanel provision provider.
 */
class Provider extends Category implements ProviderInterface
{
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
            ->setName('SPanel')
            ->setDescription('Create and manage SPanel accounts and resellers using the SPanel API')
            ->setLogoUrl('https://api.upmind.io/images/logos/provision/spanel-logo.png');
    }

    /**
     * @inheritDoc
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function create(CreateParams $params): AccountInfo
    {
        if (!$params->domain) {
            $this->errorResult('Domain name is required');
        }

        $username = $params->username ?? $this->generateUsername($params->domain);

        try {
            $this->api()->createAccount($params, $username);

            return $this->_getInfo($params->username, 'Account created');
        } catch (Throwable $e) {
            $this->handleException($e);
        }
    }

    protected function generateUsername(string $base): string
    {
        return substr(
            preg_replace('/^[^a-z]+/', '', preg_replace('/[^a-z0-9]/', '', strtolower($base))),
            0,
            $this->getMaxUsernameLength()
        );
    }

    protected function getMaxUsernameLength(): int
    {
        return 16;
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \RuntimeException
     */
    protected function _getInfo(string $username, string $message): AccountInfo
    {
        $info = $this->api()->getAccountData($username);

        return AccountInfo::create($info)->setMessage($message);
    }

    /**
     * @inheritDoc
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function getInfo(AccountUsername $params): AccountInfo
    {
        try {
            return $this->_getInfo($params->username, 'Account info retrieved');
        } catch (Throwable $e) {
            $this->handleException($e);
        }
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function getUsage(AccountUsername $params): AccountUsage
    {
        try {
            $usage = $this->api()->getAccountUsage($params->username);

            return AccountUsage::create()
                ->setUsageData($usage);
        } catch (Throwable $e) {
            $this->handleException($e);
        }
    }

    /**
     * @inheritDoc
     */
    public function getLoginUrl(GetLoginUrlParams $params): LoginUrl
    {
        return LoginUrl::create()
            ->setLoginUrl(sprintf('https://%s/spanel/login', $this->configuration->hostname));
    }

    /**
     * @inheritDoc
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function changePassword(ChangePasswordParams $params): EmptyResult
    {
        try {
            if (!$this->isValidPassword($params->password)) {
                $this->errorResult('The password must be at least 8 characters long and contain at least one letter and one number.');
            }

            $this->api()->updatePassword($params->username, $params->password);

            return $this->emptyResult('Password changed');
        } catch (Throwable $e) {
            $this->handleException($e);
        }
    }


    function isValidPassword($password)
    {
        if (strlen($password) >= 8 && preg_match('/[a-zA-Z]/', $password) && preg_match('/\d/', $password)) {
            return true;
        }

        return false;
    }


    /**
     * @inheritDoc
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function changePackage(ChangePackageParams $params): AccountInfo
    {
        try {
            $this->api()->updatePackage($params->username, $params->package_name);

            return $this->_getInfo(
                $params->username,
                'Package changed'
            );
        } catch (Throwable $e) {
            $this->handleException($e);
        }
    }

    /**
     * @inheritDoc
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function suspend(SuspendParams $params): AccountInfo
    {
        try {
            $this->api()->suspendAccount($params->username, $params->reason ?? null);

            return $this->_getInfo($params->username, 'Account suspended');
        } catch (Throwable $e) {
            $this->handleException($e);
        }
    }

    /**
     * @inheritDoc
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function unSuspend(AccountUsername $params): AccountInfo
    {
        try {
            $this->api()->unsuspendAccount($params->username);

            return $this->_getInfo($params->username, 'Account unsuspended');
        } catch (Throwable $e) {
            $this->handleException($e);
        }
    }

    /**
     * @inheritDoc
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function terminate(AccountUsername $params): EmptyResult
    {
        try {
            $this->api()->deleteAccount($params->username);

            return $this->emptyResult('Account deleted');
        } catch (Throwable $e) {
            $this->handleException($e);
        }
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
    protected function handleException(Throwable $e, array $data = [], array $debug = [], ?string $message = null): void
    {
        if ($e instanceof ProvisionFunctionError) {
            throw $e->withData(
                array_merge($e->getData(), $data)
            )->withDebug(
                array_merge($e->getDebug(), $debug)
            );
        }

        // let the provision system handle this one
        throw $e;
    }

    protected function api(): Api
    {
        if (isset($this->api)) {
            return $this->api;
        }

        return $this->api = new Api($this->configuration, $this->getGuzzleHandlerStack());
    }
}
