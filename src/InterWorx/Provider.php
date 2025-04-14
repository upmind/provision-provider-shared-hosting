<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\InterWorx;

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
use Upmind\ProvisionProviders\SharedHosting\InterWorx\Data\Configuration;

/**
 * InterWorx provision provider.
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
            ->setName('InterWorx')
            ->setDescription('Create and manage InterWorx accounts and resellers using the InterWorx API')
            ->setLogoUrl('https://api.upmind.io/images/logos/provision/interworx-logo.png');
    }

    /**
     * @inheritDoc
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function create(CreateParams $params): AccountInfo
    {
        $asReseller = boolval($params->as_reseller ?? false);

        if (!$asReseller && !$params->domain) {
            $this->errorResult('Domain name is required');
        }

        $username = $params->username ?? $this->generateUsername($params->domain);

        try {
            $this->api()->createAccount(
                $params,
                $username,
                $asReseller,
            );

            if ($asReseller) {
                return $this->_getInfo($username, true, 'Reseller account created');
            }

            return $this->_getInfo($params->domain, false, 'Account created');
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
    protected function _getInfo(string $domain, bool $isReseller, string $message): AccountInfo
    {
        if ($isReseller) {
            $info = $this->api()->getResellerData($domain);
        } else {
            $info = $this->api()->getAccountData($domain);
        }

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
            if (isset($params->is_reseller) && boolval($params->is_reseller)) {
                return $this->_getInfo(
                    $params->username,
                    true,
                    'Account info retrieved',
                );
            }

            $domain = $this->api()->getDomainName($params->username);

            return $this->_getInfo(
                $domain,
                false,
                'Account info retrieved',
            );
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
            if (isset($params->is_reseller) && boolval($params->is_reseller)) {
                $usage = $this->api()->getResellerAccountUsage(
                    $params->username,
                );

                return AccountUsage::create()
                    ->setUsageData($usage);
            }

            if (!$params->domain) {
                $domain = $this->api()->getDomainName($params->username);
            } else {
                $domain = $params->domain;
            }

            $usage = $this->api()->getAccountUsage($domain);

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
        $this->assertNotRoot($params->username);

        $url = sprintf(
            'https://%s:%s/%s/',
            $this->configuration->hostname,
            $this->configuration->port,
            $params->is_reseller ? 'nodeworx' : 'siteworx'
        );

        if (!$params->is_reseller) {
            $url .= '?domain=' . urlencode((string)$params->domain);
        }

        return LoginUrl::create()->setLoginUrl($url);
    }

    /**
     * @inheritDoc
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function changePassword(ChangePasswordParams $params): EmptyResult
    {
        $this->assertNotRoot($params->username);

        try {
            $domain = $this->api()->getDomainName($params->username);

            $this->api()->updatePassword($domain, $params->password);

            return $this->emptyResult('Password changed');
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
    public function changePackage(ChangePackageParams $params): AccountInfo
    {
        try {
            $domain = $this->api()->getDomainName($params->username);

            $this->api()->updatePackage($domain, $params->package_name);

            return $this->_getInfo(
                $domain,
                false,
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
            if (!$params->domain) {
                $domain = $this->api()->getDomainName($params->username);
            } else {
                $domain = $params->domain;
            }

            $this->api()->suspendAccount($domain, $params->reason ?? null);

            return $this->_getInfo($domain, false, 'Account suspended');
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
            if (isset($params->is_reseller) && boolval($params->is_reseller)) {
                $this->errorResult('Unsuspend reseller account not supported');
            }

            $this->api()->unsuspendAccount($params->username);

            if (!$params->domain) {
                $domain = $this->api()->getDomainName($params->username);
            } else {
                $domain = $params->domain;
            }

            return $this->_getInfo($domain, false, 'Account unsuspended');
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
            if (isset($params->is_reseller) && boolval($params->is_reseller)) {
                $this->api()->deleteReseller($params->username);

                return $this->emptyResult('Account deleted');
            }

            if (!$params->domain) {
                $domain = $this->api()->getDomainName($params->username);
            } else {
                $domain = $params->domain;
            }

            $this->api()->deleteAccount($domain);

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
     * @param string $username
     */
    protected function assertNotRoot($username)
    {
        if (0 === strcasecmp(trim((string)$username), $this->configuration->username)) {
            $this->errorResult('Cannot perform this action on configuration user itself');
        }

        if (0 === strcasecmp(trim((string)$username), 'root')) {
            $this->errorResult('Cannot perform this action on root');
        }
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

        return $this->api = new Api($this->configuration, $this->getLogger());
    }
}
