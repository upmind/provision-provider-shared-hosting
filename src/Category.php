<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting;

use Upmind\ProvisionBase\Provider\BaseCategory;
use Upmind\ProvisionBase\Provider\DataSet\AboutData;
use Upmind\ProvisionProviders\SharedHosting\Data\AccountInfo;
use Upmind\ProvisionProviders\SharedHosting\Data\AccountUsage;
use Upmind\ProvisionProviders\SharedHosting\Data\CreateParams;
use Upmind\ProvisionProviders\SharedHosting\Data\EmptyResult;
use Upmind\ProvisionProviders\SharedHosting\Data\GetLoginUrlParams;
use Upmind\ProvisionProviders\SharedHosting\Data\AccountUsername;
use Upmind\ProvisionProviders\SharedHosting\Data\ChangePackageParams;
use Upmind\ProvisionProviders\SharedHosting\Data\ChangePasswordParams;
use Upmind\ProvisionProviders\SharedHosting\Data\GrantResellerParams;
use Upmind\ProvisionProviders\SharedHosting\Data\LoginUrl;
use Upmind\ProvisionProviders\SharedHosting\Data\ResellerPrivileges;
use Upmind\ProvisionProviders\SharedHosting\Data\SuspendParams;

/**
 * This provision category contains the common functions used in provisioning
 * flows for accounts/websites on various popular shared hosting platforms.
 */
abstract class Category extends BaseCategory
{
    /**
     * @inheritDoc
     */
    public static function aboutCategory(): AboutData
    {
        return AboutData::create()
            ->setName('Shared WebHosting')
            ->setDescription(
                'Provision and manage accounts on common shared hosting'
                    . ' platforms such as cPanel/WHM and Plesk'
            )
            ->setIcon('laptop');
    }

    /**
     * Creates a web hosting account / website and returns the `username` which
     * can be used to identify the account in subsequent requests, and other
     * account information.
     */
    abstract public function create(CreateParams $params): AccountInfo;

    /**
     * Gets information about a hosting account such as the main domain name,
     * whether, or not, it is suspended, the hostname of it's server, nameservers
     * etc.
     */
    abstract public function getInfo(AccountUsername $params): AccountInfo;

    /**
     * Gets usage information about an account/reseller such as disk space,
     * bandwidth, number of sub-accounts etc.
     */
    abstract public function getUsage(AccountUsername $params): AccountUsage;

    /**
     * Obtains a signed URL which a user can be redirected to which
     * automatically logs them into their account.
     */
    abstract public function getLoginUrl(GetLoginUrlParams $params): LoginUrl;

    /**
     * Changes the password of the hosting account.
     */
    abstract public function changePassword(ChangePasswordParams $params): EmptyResult;

    /**
     * Update the product/package a hosting account is set to.
     */
    abstract public function changePackage(ChangePackageParams $params): AccountInfo;

    /**
     * Suspends services for a hosting account.
     */
    abstract public function suspend(SuspendParams $params): AccountInfo;

    /**
     * Un-suspends services for a hosting account.
     */
    abstract public function unSuspend(AccountUsername $params): AccountInfo;

    /**
     * Completely delete a hosting account.
     */
    abstract public function terminate(AccountUsername $params): EmptyResult;

    /**
     * Grants reseller privileges to a web hosting account, if supported.
     */
    abstract public function grantReseller(GrantResellerParams $params): ResellerPrivileges;

    /**
     * Revokes reseller privileges from a web hosting account, if supported.
     */
    abstract public function revokeReseller(AccountUsername $params): ResellerPrivileges;

    /**
     * Create an empty result.
     */
    protected function emptyResult($message, $data = [], $debug = []): EmptyResult
    {
        return EmptyResult::create($data)
            ->setMessage($message)
            ->setDebug($debug);
    }
}
