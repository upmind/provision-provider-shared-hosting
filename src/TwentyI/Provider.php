<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\TwentyI;

use Carbon\Carbon;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use stdClass;
use Throwable;
use Upmind\ProvisionBase\Provider\Contract\ProviderInterface;
use Upmind\ProvisionProviders\SharedHosting\Category as SharedHosting;
use Upmind\ProvisionBase\Provider\DataSet\AboutData;
use Upmind\ProvisionProviders\SharedHosting\Data\AccountInfo;
use Upmind\ProvisionProviders\SharedHosting\Data\AccountUsage;
use Upmind\ProvisionProviders\SharedHosting\Data\AccountUsername;
use Upmind\ProvisionProviders\SharedHosting\Data\ChangePackageParams;
use Upmind\ProvisionProviders\SharedHosting\Data\ChangePasswordParams;
use Upmind\ProvisionProviders\SharedHosting\Data\ChangePrimaryDomainParams;
use Upmind\ProvisionProviders\SharedHosting\Data\CreateParams;
use Upmind\ProvisionProviders\SharedHosting\Data\EmptyResult;
use Upmind\ProvisionProviders\SharedHosting\Data\GetLoginUrlParams;
use Upmind\ProvisionProviders\SharedHosting\Data\GrantResellerParams;
use Upmind\ProvisionProviders\SharedHosting\Data\LoginUrl;
use Upmind\ProvisionProviders\SharedHosting\Data\ResellerPrivileges;
use Upmind\ProvisionProviders\SharedHosting\Data\SuspendParams;
use Upmind\ProvisionProviders\SharedHosting\Data\UnitsConsumed;
use Upmind\ProvisionProviders\SharedHosting\Data\UsageData;
use Upmind\ProvisionProviders\SharedHosting\TwentyI\Data\TwentyICredentials;

/**
 * Provision 20i shared hosting packages via their reseller API.
 *
 * @link https://my.20i.com/reseller/apiDoc
 */
class Provider extends SharedHosting implements ProviderInterface
{
    /**
     * @var Api|null
     */
    protected $api;

    /**
     * @var TwentyICredentials
     */
    protected $configuration;

    public function __construct(TwentyICredentials $configuration)
    {
        $this->configuration = $configuration;
    }

    public static function aboutProvider(): AboutData
    {
        return AboutData::create()
            ->setName('20i Hosting')
            ->setDescription('Create and manage 20i hosting accounts via the reseller API')
            ->setLogoUrl('https://api.upmind.io/images/logos/provision/20i-logo@2x.png');
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function create(CreateParams $params): AccountInfo
    {
        if (!$params->domain) {
            $this->errorResult('Domain name is required');
        }

        if (!empty($params->location)) {
            $locationId = $this->getLocationId($params->location);
        }

        $hostingId = $this->api()->createPackage(
            $params->package_name,
            $params->domain,
            $locationId ?? null,
            $customerId = $this->findOrCreateUser($params)
        );

        return $this->getAccountInfoData($hostingId)
            ->setCustomerId($customerId);
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function getInfo(AccountUsername $params): AccountInfo
    {
        $infoResult = $this->getAccountInfoData($params->username, $params->domain);

        if ($params->customer_id) {
            $infoResult->setCustomerId($params->customer_id);
        }

        return $infoResult;
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function getUsage(AccountUsername $params): AccountUsage
    {
        $info = $this->getPackageInfo($params->username, $params->domain);
        $usage = $this->api()->getPackageUsage($info->username);
        $limits = $info->limits;

        $websites = UnitsConsumed::create()
            ->setUsed(count($info->names))
            ->setLimit($limits->domains !== 'INF' ? $limits->domains : null);

        $disk = UnitsConsumed::create()
            ->setUsed($usage->DiskMb)
            ->setLimit($limits->webspace !== 'INF' ? $limits->webspace : null);

        $bandwidth = UnitsConsumed::create()
            ->setUsed($usage->Bandwidth->MbIn + $usage->Bandwidth->MbOut)
            ->setLimit($limits->bandwidth !== 'INF' ? $limits->bandwidth : null);

        $usage = UsageData::create()
            ->setWebsites($websites)
            ->setDiskMb($disk)
            ->setBandwidthMb($bandwidth);

        return AccountUsage::create()
            ->setUsageData($usage);
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function getLoginUrl(GetLoginUrlParams $params): LoginUrl
    {
        $info = $this->getPackageInfo($params->username, $params->domain);

        $stackUser = Arr::first($info->stackUsers, function ($stackUser) use ($params) {
            return $params->customer_id && Str::start($params->customer_id, 'stack-user:') === $stackUser;
        }, Arr::first($info->stackUsers));

        if (!$stackUser) {
            $this->errorResult('Hosting package has no stack user assigned');
        }

        [$loginUrl, $ttl] = $this->api()->getLoginUrl($stackUser, $info->web->name);

        if (Str::startsWith($loginUrl, 'http://')) {
            // force HTTPS
            $loginUrl = Str::replaceFirst('http://', 'https://', $loginUrl);
        }

        return LoginUrl::create()
            ->setLoginUrl($loginUrl)
            ->setExpires(Carbon::now()->addSeconds($ttl))
            ->setForIp(null);
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function grantReseller(GrantResellerParams $params): ResellerPrivileges
    {
        $this->errorResult('Function not available for 20i accounts');
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function revokeReseller(AccountUsername $params): ResellerPrivileges
    {
        $this->errorResult('Function not available for 20i accounts');
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function changePassword(ChangePasswordParams $params): EmptyResult
    {
        $info = $this->getPackageInfo($params->username, $params->domain ?? null);

        $stackUser = Arr::first($info->stackUsers, function ($stackUser) use ($params) {
            return $params->customer_id && Str::start($params->customer_id, 'stack-user:') === $stackUser;
        }, Arr::first($info->stackUsers));

        if (!$stackUser) {
            $this->errorResult('Hosting package has no stack user assigned');
        }

        $this->api()->changeStackUserPassword($stackUser, $params->password);

        return EmptyResult::create()->setMessage('Password changed');
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function changePackage(ChangePackageParams $params): AccountInfo
    {
        $planId = $params->package_name;

        $packageInfo = $this->getPackageInfo($params->username, $params->domain); // throws error if hosting is deleted
        $hostingInfo = $packageInfo->web;
        $planInfo = $this->api()->getPlanInfo($planId); // throws error if plan not found

        if ($hostingInfo->platform !== $planInfo->platform) {
            // check platforms match - 20i do not support change of platform
            $errorMessage = sprintf(
                'Cannot change platform from %s to %s',
                $hostingInfo->platform,
                $planInfo->platform
            );
            $this->errorResult($errorMessage, [
                'hosting_id' => $packageInfo->username,
                'new_plan_id' => $planId,
            ]);
        }

        $this->api()->changePackagePlan($packageInfo->username, $planId);

        return $this->getAccountInfoData($packageInfo->username);
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function changePrimaryDomain(ChangePrimaryDomainParams $params): AccountInfo
    {
        $this->errorResult('Operation not supported');
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function suspend(SuspendParams $params): AccountInfo
    {
        $infoResult = $this->getAccountInfoData($params->username, $params->domain) // throws error if hosting deleted
            ->setSuspendReason($params->reason);

        if ($infoResult->suspended) {
            return $infoResult->setMessage('Hosting package already suspended');
        }

        $this->api()->disablePackage($infoResult->username);

        return $infoResult->setMessage('Hosting package suspended')
            ->setSuspended(true);
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function unSuspend(AccountUsername $params): AccountInfo
    {
        $infoResult = $this->getAccountInfoData($params->username, $params->domain) // throws error if hosting deleted
            ->setSuspendReason(null);

        if (!$infoResult->suspended) {
            return $infoResult->setMessage('Hosting package already unsuspended');
        }

        $this->api()->enablePackage($infoResult->username);

        return $infoResult->setMessage('Hosting package unsuspended')
            ->setSuspended(false);
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function terminate(AccountUsername $params): EmptyResult
    {
        $infoResult = $this->getAccountInfoData($params->username, $params->domain); // throws error if already deleted

        $this->api()->terminatePackage($infoResult->username);

        return EmptyResult::create()
            ->setMessage('Hosting package deleted');
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    protected function getAccountInfoData($hostingId, ?string $domain = null): AccountInfo
    {
        $info = $this->getPackageInfo($hostingId, $domain);

        $domain = $info->web->name;
        $ip = $info->web->info->ip4Address ?? null;
        $serverHost = $this->configuration->control_panel_hostname ?: ($ip ?? 'unknown.host');
        $packageName = $info->web->typeRef;
        $suspended = !$info->status;
        $suspendReason = null;
        $reseller = false;

        return AccountInfo::create()
            ->setUsername((string)$info->username)
            ->setDomain($domain)
            ->setReseller($reseller)
            ->setServerHostname($serverHost)
            ->setPackageName((string)$packageName)
            ->setSuspended($suspended)
            ->setSuspendReason($suspendReason)
            ->setLocation($info->web->info->zone ?? null)
            ->setIp($ip);
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    protected function getPackageInfo($hostingId, ?string $domain = null): stdClass
    {
        try {
            $info = $this->api()->getPackageInfo($hostingId);
            $info->username = $hostingId;

            return $info;
        } catch (Throwable $e) {
            if ($domain && Str::contains($e->getMessage(), '(not found)')) {
                try {
                    $info = $this->api()->getPackageInfo($domain);
                    $info->username = $info->id;
                    return $info;
                } catch (Throwable $e) {
                    throw $e;
                }
            }

            throw $e;
        }
    }

    /**
     * Combine hosting id and stack user reference to return a single username
     * string.
     *
     * @param int|null $hostingId Hosting package id E.g., 1234
     * @param string|null $stackUser Stack user reference E.g, stack-user:4567
     *
     * @return string Combined username string E.g., hosting:1234|stack-user:4567
     */
    protected function getCombinedUsername(?int $hostingId, ?string $stackUser): string
    {
        $parts = [];

        if ($hostingId) {
            $parts[] = sprintf('hosting:%s', $hostingId);
        }

        if ($stackUser) {
            $parts[] = is_numeric($stackUser)
                ? sprintf('stack-user:%s', $stackUser)
                : $stackUser;
        }

        return implode('|', $parts);
    }

    /**
     * Parse hosting id and stack user reference from the username string (which
     * may contain just hosting id, or a combination of hosting id and stack user
     * reference).
     *
     * @param string $username E.g., 'hosting:1235|stack-user:5678'
     *
     * @return array E.g., [1235, 'stack-user:5678']
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    protected function getHostingIdAndStackUser($username): array
    {
        if (is_numeric($username)) {
            $hostingId = $username;
        } else {
            $parts = explode('|', (string)$username);

            foreach ($parts as $part) {
                if (Str::startsWith($part, 'hosting:')) {
                    $hostingId = (int)Str::after($part, 'hosting:');
                }

                if (Str::startsWith($part, 'stack-user:')) {
                    $stackUser = $part;
                }
            }
        }

        if (empty($hostingId)) {
            $this->errorResult('Unable to determine hosting id', ['username' => $username]);
        }

        return [$hostingId, $stackUser ?? null];
    }

    /**
     * Find an existing stack user by email (if auto-detect enabled), or create
     * a new one.
     *
     * @return string Stack user reference
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    protected function findOrCreateUser(CreateParams $params): string
    {
        if ($params->customer_id) {
            return Str::start($params->customer_id, 'stack-user:');
        }

        // re-use customer email address for stack user

        $existingUser = $this->api()->searchForStackUser($params->email);

        if ($existingUser) {
            return $existingUser;
        }

        return $this->api()->createStackUser(
            $params->email,
            $params->customer_name,
            $params->customer_reference,
            $params->customer_address->address_1 ?? null,
            $params->customer_address->city ?? null,
            $params->customer_address->postcode ?? null,
            $params->customer_address->country_code ?? null,
            $params->customer_phone
        );
    }

    /**
     * Get the location identifier for the given location id or name.
     *
     * @param string $location Id or name
     *
     * @return string Location identifier
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    protected function getLocationId(string $location): string
    {
        $location = trim($location);
        $locations = $this->api()->listDataCentreLocations();

        foreach ($locations as $key => $value) {
            if ($location === trim($key) || $location === trim($value)) {
                return $key;
            }
        }

        $this->errorResult(sprintf('Location "%s" not found', $location), [
            'available_locations' => $locations,
        ]);
    }

    /**
     * Returns the given email address with the given domain name in the sub-folder
     * section.
     *
     * @param string $email E.g., harry@upmind.com
     * @param string $domain E.g., harrydev.uk
     *
     * @return string E.g., harry+harrydev-uk@upmind.com
     */
    protected function getEmailPlusDomain(string $email, string $domain): string
    {
        $emailParts = explode('@', $email, 2);
        $domain = preg_replace('/[^a-z0-9]/i', '-', $domain);

        return Str::contains($emailParts[0], '+')
            ? sprintf('%s-%s@%s', $emailParts[0], Str::slug($domain), $emailParts[1])
            : sprintf('%s+%s@%s', $emailParts[0], Str::slug($domain), $emailParts[1]);
    }

    protected function api(): Api
    {
        return $this->api = ($this->api = new Api(
            $this->configuration->general_api_key,
            $this->getLogger()
        ));
    }
}
