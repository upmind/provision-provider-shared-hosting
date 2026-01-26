<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\Demo;

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
use Upmind\ProvisionProviders\SharedHosting\Data\UnitsConsumed;
use Upmind\ProvisionProviders\SharedHosting\Demo\Data\Configuration;

/**
 * Stateless demo provider which doesn't actually provision anything, but will pretend to.
 */
class Provider extends Category implements ProviderInterface
{
    protected Configuration $configuration;

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
            ->setName('Demo Provider')
            ->setLogoUrl('https://api.upmind.io/images/logos/provision/demo-logo.png')
            ->setDescription('Demo provider which doesn\'t actually provision anything, but will pretend to');
    }

    /**
     * @inheritDoc
     */
    public function create(CreateParams $params): AccountInfo
    {
        $customerId = $params->customer_id ?? uniqid();
        $subscriptionId = uniqid('s-');
        $username = $params->username ?? $params->email;

        $info = $this->getAccountInfo(
            $username,
            $customerId,
            $subscriptionId,
            $params->domain
        );

        return $info->setMessage('Demo account created')
            ->setPackageName($params->package_name)
            ->setReseller(boolval($params->as_reseller));
    }

    /**
     * @inheritDoc
     */
    public function getInfo(AccountUsername $params): AccountInfo
    {
        return $this->getAccountInfo(
            $params->username,
            $params->customer_id,
            $params->subscription_id,
            $params->domain
        )->setMessage('Demo account info retrieved');
    }

    public function getUsage(AccountUsername $params): AccountUsage
    {
        return AccountUsage::create()
            ->setUsageData([
                'disk_mb' => UnitsConsumed::create()
                    ->setUsed(150)
                    ->setLimit(500)
                    ->setUsedPc(round(150 / 500 * 100, 2) . '%'),
                'bandwidth_mb' => UnitsConsumed::create()
                    ->setUsed(4000)
                    ->setLimit(10000)
                    ->setUsedPc(round(4000 / 10000 * 100, 2) . '%'),
                'inodes' => UnitsConsumed::create()
                    ->setUsed(1000)
                    ->setLimit(5000)
                    ->setUsedPc(round(1000 / 5000 * 100, 2) . '%'),
            ])->setMessage('Account usage data retrieved');
    }

    /**
     * @inheritDoc
     */
    public function getLoginUrl(GetLoginUrlParams $params): LoginUrl
    {
        return LoginUrl::create()
            ->setMessage('Demo login URL generated')
            ->setLoginUrl(sprintf('https://%s.com/auth/login/example', $this->configuration->hostname));
    }

    /**
     * @inheritDoc
     */
    public function changePassword(ChangePasswordParams $params): EmptyResult
    {
        return $this->emptyResult('Demo password changed');
    }

    /**
     * @inheritDoc
     */
    public function changePackage(ChangePackageParams $params): AccountInfo
    {
        $info = $this->getAccountInfo(
            $params->username,
            $params->customer_id,
            $params->subscription_id,
            $params->domain
        );
        return $info->setMessage('Demo package changed')
            ->setPackageName($params->package_name)
            ->setReseller(boolval($params->as_reseller));
    }

    public function changePrimaryDomain(ChangePrimaryDomainParams $params): AccountInfo
    {
        $info = $this->getAccountInfo(
            $params->username,
            $params->customer_id,
            $params->subscription_id,
            $params->domain
        );

        return $info->setMessage('Primary domain name changed')
            ->setDomain($params->domain);
    }

    /**
     * @inheritDoc
     */
    public function suspend(SuspendParams $params): AccountInfo
    {
        $info = $this->getAccountInfo(
            $params->username,
            $params->customer_id,
            $params->subscription_id,
            $params->domain
        );
        return $info->setMessage('Demo account suspended')
            ->setSuspended(true)
            ->setSuspendReason($params->reason);
    }

    /**
     * @inheritDoc
     */
    public function unSuspend(AccountUsername $params): AccountInfo
    {
        $info = $this->getAccountInfo(
            $params->username,
            $params->customer_id,
            $params->subscription_id,
            $params->domain
        );
        return $info->setMessage('Demo account unsuspended')
            ->setSuspended(false);
    }

    /**
     * @inheritDoc
     */
    public function terminate(AccountUsername $params): EmptyResult
    {
        return $this->emptyResult('Demo account terminated');
    }

    /**
     * @inheritDoc
     */
    public function grantReseller(GrantResellerParams $params): ResellerPrivileges
    {
        return ResellerPrivileges::create()
            ->setMessage('Demo reseller privileges granted')
            ->setReseller(true);
    }

    /**
     * @inheritDoc
     */
    public function revokeReseller(AccountUsername $params): ResellerPrivileges
    {
        return ResellerPrivileges::create()
            ->setMessage('Demo reseller privileges revoked')
            ->setReseller(true);
    }

    /**
     * @param string $username
     * @param string|int|null $customerId
     * @param string|int|null $subscriptionId
     * @param string|null $domain
     */
    protected function getAccountInfo(
        string $username,
        $customerId,
        $subscriptionId,
        ?string $domain
    ): AccountInfo {
        return AccountInfo::create()
            ->setMessage('Demo account info obtained')
            ->setCustomerId($customerId)
            ->setSubscriptionId($subscriptionId)
            ->setDomain($domain)
            ->setUsername($username)
            ->setServerHostname($this->configuration->hostname)
            ->setPackageName('Demo Hosting Package')
            ->setReseller(false)
            ->setSuspended(false)
            ->setNameservers([
                'ns1.' . $this->configuration->hostname,
                'ns2.' . $this->configuration->hostname,
                'ns3.' . $this->configuration->hostname,
            ])
            ->setIp('123.123.123.123');
    }
}
