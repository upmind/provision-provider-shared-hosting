<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\Enhance;

use GuzzleHttp\Client;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\MessageFormatter;
use GuzzleHttp\Middleware;
use GuzzleHttp\Promise\Utils as PromiseUtils;
use GuzzleHttp\Psr7\Message;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Psr\Http\Message\MessageInterface;
use Psr\Log\LogLevel;
use Throwable;
use Upmind\EnhanceSdk\ApiException;
use Upmind\EnhanceSdk\Model\DomainIp;
use Upmind\EnhanceSdk\Model\LoginInfo;
use Upmind\EnhanceSdk\Model\Member;
use Upmind\EnhanceSdk\Model\NewCustomer;
use Upmind\EnhanceSdk\Model\NewMember;
use Upmind\EnhanceSdk\Model\NewSubscription;
use Upmind\EnhanceSdk\Model\NewWebsite;
use Upmind\EnhanceSdk\Model\PhpVersion;
use Upmind\EnhanceSdk\Model\Plan;
use Upmind\EnhanceSdk\Model\PlanType;
use Upmind\EnhanceSdk\Model\ResourceName;
use Upmind\EnhanceSdk\Model\Role;
use Upmind\EnhanceSdk\Model\RoleInstallationState;
use Upmind\EnhanceSdk\Model\ServerGroup;
use Upmind\EnhanceSdk\Model\ServerInfo;
use Upmind\EnhanceSdk\Model\ServerIp;
use Upmind\EnhanceSdk\Model\Status;
use Upmind\EnhanceSdk\Model\Subscription;
use Upmind\EnhanceSdk\Model\SubscriptionDedicatedServers;
use Upmind\EnhanceSdk\Model\UpdateSubscription;
use Upmind\EnhanceSdk\Model\UpdateWebsite;
use Upmind\EnhanceSdk\Model\UsedResource;
use Upmind\EnhanceSdk\Model\Website;
use Upmind\EnhanceSdk\Model\WebsiteAppKind;
use Upmind\EnhanceSdk\Model\WebsiteKind;
use Upmind\ProvisionBase\Exception\ProvisionFunctionError;
use Upmind\ProvisionBase\Helper;
use Upmind\ProvisionBase\Provider\Contract\LogsDebugData;
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
use Upmind\ProvisionProviders\SharedHosting\Data\ResellerUsageData;
use Upmind\ProvisionProviders\SharedHosting\Data\SuspendParams;
use Upmind\ProvisionProviders\SharedHosting\Enhance\Data\Configuration;

class Provider extends Category implements ProviderInterface
{
    /**
     * Subscription allowance name which grant's reseller capabilities.
     */
    protected const ALLOWANCE_RESELLER = 'allowReselling';

    /**
     * @var Configuration
     */
    protected $configuration;

    /**
     * @var mixed[]|null
     */
    protected $meta;

    /**
     * @var Api
     */
    protected $api;

    /**
     * Memoized hostname of the configured org's control panel.
     *
     * @var string|false
     */
    protected $controlPanelHostname;

    /**
     * Memoized flag indicating whether the configured org is the master org.
     *
     * @var bool|null
     */
    protected $isMasterOrg;

    /**
     * Array containing the history of guzzle requests for this instance.
     *
     * @var array<Message[]>
     */
    protected $guzzleHistory = [];

    public static function aboutProvider(): AboutData
    {
        return AboutData::create()
            ->setName('Enhance')
            ->setDescription('Create and manage Enhance accounts and resellers using the Enhance API')
            ->setLogoUrl('https://api.upmind.io/images/logos/provision/enhance-logo@2x.png');
    }

    public function __construct(Configuration $configuration)
    {
        $this->configuration = $configuration;
    }

    public function create(CreateParams $params): AccountInfo
    {
        $customerCreated = false;

        try {
            $plan = $this->findPlan($params->package_name);

            $location = trim($params->location ?? '');
            if ($plan->getPlanType() === PlanType::DEDICATED || Str::startsWith($location, 'dedicated:')) {
                // Find server for subscription placement
                if (empty($location)) {
                    $this->errorResult("Location (server id or name) is required for dedicated plans");
                }

                $server = $this->findServer(Str::after($location, 'dedicated:'), true);
                $dedicatedServerId = $server->getId();

                // Check that the server is in the configured dedicated server group, if set
                if ($this->configuration->dedicated_server_group) {
                    $dedicatedGroup = $this->findServerGroup($this->configuration->dedicated_server_group, false);

                    if (!$dedicatedGroup) {
                        $this->errorResult("Dedicated server group not found", [
                            'dedicated_server_group' => $this->configuration->dedicated_server_group,
                        ]);
                    }

                    if ($server->getGroupId() !== $dedicatedGroup->getId()) {
                        $this->errorResult("Server is not in the configured dedicated server group", [
                            'server_id' => $dedicatedServerId,
                            'server_name' => $server->getFriendlyName(),
                            'server_group_id' => $server->getGroupId(),
                            'dedicated_server_group_id' => $dedicatedGroup->getId(),
                            'dedicated_server_group_name' => $dedicatedGroup->getName(),
                        ]);
                    }
                }

                // Check the server is not already in use by an existing subscription
                if ($server->getDedicatedSubscription()) {
                    $this->errorResult("Dedicated server already in use by an existing subscription", [
                        'server_id' => $dedicatedServerId,
                        'server_name' => $server->getFriendlyName(),
                        'existing_subscription' => $server->getDedicatedSubscription()->jsonSerialize(),
                    ]);
                }
            } elseif ($location && !$this->configuration->create_subscription_only) {
                if (!$this->isMasterOrg()) {
                    // Pre-check here to prevent ugly 403 error from Enhance API below
                    $this->errorResult("Location (server group) unavailable for reseller orgs");
                }

                // Find server group for website placement
                $serverGroup = $this->findServerGroup($location);
                $this->assertGroupHasApplicationServer($serverGroup);

                $serverGroupId = $serverGroup->getId();
            }

            if ($customerId = $params->customer_id) {
                $email = $this->findOwnerMember($customerId, $params->email)->getEmail();
            } else {
                $customerId = $this->createCustomer(
                    $params->customer_name ?? $params->email,
                    $params->email,
                    $params->password ?: $this->generateRandomPassword()
                );
                $email = $params->email;
                $customerCreated = true;
            }

            $domain = (!empty($params->domain) && $this->configuration->remove_www)
                ? preg_replace('/^www\.(.+)/i', '$1', $params->domain)
                : $params->domain;

            $subscriptionId = $this->createSubscription($customerId, $plan->getId(), $dedicatedServerId ?? null);

            if ($domain && !$this->configuration->create_subscription_only) {
                $this->createWebsite($customerId, $subscriptionId, $domain, $serverGroupId ?? null);
            }

            return $this->getSubscriptionInfo($customerId, $subscriptionId, $domain, $email)
                ->setMessage(sprintf(
                    '%s created',
                    $this->configuration->create_subscription_only ? 'Subscription' : 'Website'
                ));
        } catch (Throwable $e) {
            if ($customerCreated && isset($customerId)) {
                try {
                    $this->deleteCustomer($customerId);
                } catch (Throwable $deleteException) {
                    // ignore
                    $errorData = [
                        'customer_delete' => [
                            'error' => $deleteException->getMessage(),
                        ],
                    ];
                }
            }

            throw $this->handleException($e, $errorData ?? []);
        }
    }

    public function suspend(SuspendParams $params): AccountInfo
    {
        try {
            if (!$params->subscription_id) {
                throw $this->errorResult('Subscription ID is required');
            }

            $customerId = $params->customer_id ?: $this->findCustomerIdByEmail($params->username);

            $updateSubscription = (new UpdateSubscription())
                ->setIsSuspended(true);

            $this->api()->subscriptions()->updateSubscription(
                $customerId,
                $params->subscription_id,
                $updateSubscription
            );

            $info = $this->getSubscriptionInfo(
                $customerId,
                intval($params->subscription_id),
                $params->domain,
                $params->username
            );

            return $info->setMessage('Subscription suspended')
                ->setSuspendReason($params->reason);
        } catch (Throwable $e) {
            throw $this->handleException($e);
        }
    }

    public function unSuspend(AccountUsername $params): AccountInfo
    {
        try {
            if (!$params->subscription_id) {
                throw $this->errorResult('Subscription ID is required');
            }

            $customerId = $params->customer_id ?: $this->findCustomerIdByEmail($params->username);

            $updateSubscription = (new UpdateSubscription())
                ->setIsSuspended(false);

            $this->api()->subscriptions()->updateSubscription(
                $customerId,
                $params->subscription_id,
                $updateSubscription
            );

            $info = $this->getSubscriptionInfo(
                $customerId,
                intval($params->subscription_id),
                $params->domain,
                $params->username
            );

            return $info->setMessage('Subscription unsuspended')
                ->setSuspendReason(null);
        } catch (Throwable $e) {
            throw $this->handleException($e);
        }
    }

    public function terminate(AccountUsername $params): EmptyResult
    {
        try {
            if (!$params->subscription_id) {
                throw $this->errorResult('Subscription ID is required');
            }

            $customerId = $params->customer_id ?: $this->findCustomerIdByEmail($params->username);

            $this->api()->subscriptions()
                ->deleteSubscription($customerId, $params->subscription_id, 'false');

            return $this->emptyResult('Subscription deleted');
        } catch (Throwable $e) {
            throw $this->handleException($e);
        }
    }

    public function getInfo(AccountUsername $params): AccountInfo
    {
        try {
            $customerId = $params->customer_id ?: $this->findCustomerIdByEmail($params->username);
            $subscriptionId = intval($params->subscription_id) ?: null;

            return $this->getSubscriptionInfo(
                $customerId,
                $subscriptionId,
                $params->domain,
                $params->username
            );
        } catch (Throwable $e) {
            throw $this->handleException($e);
        }
    }

    public function getUsage(AccountUsername $params): AccountUsage
    {
        try {
            $customerId = $params->customer_id ?: $this->findCustomerIdByEmail($params->username);
            $subscriptionId = intval($params->subscription_id) ?: null;

            return $this->getSubscriptionUsage(
                $customerId,
                $subscriptionId,
                $params->domain
            );
        } catch (Throwable $e) {
            throw $this->handleException($e);
        }
    }

    public function getLoginUrl(GetLoginUrlParams $params): LoginUrl
    {
        try {
            $customerId = $params->customer_id ?: $this->findCustomerIdByEmail($params->username);
            $subscriptionId = intval($params->subscription_id) ?: null;

            $loginUrl = $this->getSsoUrl($customerId, $subscriptionId, $params->domain);

            return LoginUrl::create()
                ->setLoginUrl($loginUrl)
                ->setDebug(['control_panel_hostname' => $this->getControlPanelHostname($customerId)]);
        } catch (Throwable $e) {
            throw $this->handleException($e);
        }
    }

    public function changePassword(ChangePasswordParams $params): EmptyResult
    {
        try {
            if (!$params->customer_id) {
                throw $this->errorResult('Customer ID is required');
            }

            $owner = $this->findOwnerMember($params->customer_id, $params->username);

            $this->api()->logins()->startPasswordRecovery(
                ['email' => $owner->getEmail()],
                $params->customer_id
            );

            return $this->emptyResult('Password reset initiated - please check your email');
        } catch (Throwable $e) {
            throw $this->handleException($e);
        }
    }

    public function changePackage(ChangePackageParams $params): AccountInfo
    {
        try {
            if (!$params->subscription_id) {
                throw $this->errorResult('Subscription ID is required');
            }

            $customerId = $params->customer_id ?: $this->findCustomerIdByEmail($params->username);

            $plan = $this->findPlan($params->package_name);

            $updateSubscription = (new UpdateSubscription())
                ->setPlanId($plan->getId());

            $this->api()->subscriptions()->updateSubscription(
                $customerId,
                $params->subscription_id,
                $updateSubscription
            );

            $info = $this->getSubscriptionInfo(
                $customerId,
                intval($params->subscription_id),
                $params->domain,
                $params->username
            );

            return $info->setMessage('Subscription plan updated');
        } catch (Throwable $e) {
            throw $this->handleException($e);
        }
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
     */
    public function grantReseller(GrantResellerParams $params): ResellerPrivileges
    {
        throw $this->errorResult('Operation not supported');
    }

    public function revokeReseller(AccountUsername $params): ResellerPrivileges
    {
        throw $this->errorResult('Operation not supported');
    }

    /**
     * Determine whether this configuration's Enhance CP is the given version or greater.
     */
    protected function isEnhanceVersion(string $requireVersion): bool
    {
        $version = $this->getEnhanceMeta()['version'];

        return true === version_compare($version, $requireVersion, '>=');
    }

    /**
     * Assert that this configuration's Enhance CP is the given version or greater.
     *
     * @throws ProvisionFunctionError
     */
    protected function requireEnhanceVersion(string $requireVersion, string $operation = 'this operation'): void
    {
        if (!$this->isEnhanceVersion($requireVersion)) {
            throw $this->errorResult(
                sprintf('Control panel v%s is required for %s', $requireVersion, $operation)
            );
        }
    }

    /**
     * Get Enhance CP status and version.
     */
    protected function getEnhanceMeta(): array
    {
        if (isset($this->meta)) {
            return $this->meta;
        }

        $requests = [
            'status' => $this->api()->install()->orchdStatusAsync()->then(function ($status) {
                return json_decode($status) ?? $status;
            }),
            'version' => $this->api()->install()->orchdVersionAsync(),
        ];

        if (!isset($this->isMasterOrg)) {
            $requests['master_org'] = $this->api()->orgs()->getOrgAsync($this->configuration->org_id)
                ->then(function ($org) {
                    return $this->isMasterOrg($org);
                });
        }

        return PromiseUtils::all($requests)
            ->then(function ($meta) {
                $meta['master_org'] ??= $this->isMasterOrg;
                $this->meta = $meta;
                return $meta;
            })
            ->wait();
    }

    protected function findCustomerIdByEmail(string $email): string
    {
        $offset = 0;
        $limit = 500;

        do {
            $customers = $this->api()->customers()->getOrgCustomers($this->configuration->org_id, $offset, $limit);
            $offset += $limit;

            foreach ($customers->getItems() as $customer) {
                if ($email === $customer->getOwnerEmail()) {
                    return $customer->getId();
                }
            }
        } while ($offset + $limit < $customers->getTotal());

        throw $this->errorResult('Customer not found', ['email' => $email]);
    }

    /**
     * @throws ApiException
     */
    protected function getSubscriptionInfo(
        string $customerId,
        ?int $subscriptionId,
        ?string $domain,
        ?string $email = null
    ): AccountInfo {
        $website = $this->findWebsite($customerId, $subscriptionId, $domain, false);

        if (!$website && !empty($domain)) {
            // deleted domain - try again with no domain name
            $website = $this->findWebsite($customerId, $subscriptionId, null, false);
        }

        $subscriptionId = $subscriptionId ?? $website->getSubscriptionId();
        if (empty($subscriptionId)) {
            $this->errorResult('Website not associated with a subscription', [
                'customer_id' => $customerId,
                'website' => $website->jsonSerialize(),
            ]);
        }

        $subscription = $this->api()->subscriptions()
            ->getSubscription($customerId, $subscriptionId);

        if ($subscription->getStatus() === Status::DELETED) {
            throw $this->errorResult('Subscription terminated', ['subscription' => $subscription->jsonSerialize()]);
        }

        if ($dedicatedServers = $subscription->getDedicatedServers()) {
            if ($appServer = $dedicatedServers->getAppServer()) {
                $location = $appServer->getName();
            }
        }

        if ($this->isEnhanceVersion('12.0.0')) {
            $nameservers = array_map(function ($ns) {
                /** @var DomainIp|string $ns */
                return $ns instanceof DomainIp ? $ns->getDomain() : $ns;
            }, $this->api()->branding()->getBranding($this->configuration->org_id)->getNameServers());
        } else {
            // Backwards incompatible change in Enhance v12 to branding API causes this to break
            // Let's just return empty nameservers to avoid errors in older versions
            $nameservers = [];
        }

        if (empty($location) && isset($website)) {
            if ($serverGroup = $this->findServerGroupByServerId($website->getAppServerId())) {
                $location = $serverGroup->getName();
            }
        }

        return AccountInfo::create()
            ->setMessage('Subscription info obtained')
            ->setCustomerId($customerId)
            ->setUsername($email ?? $this->findOwnerMember($customerId)->getEmail())
            ->setSubscriptionId($subscription->getId())
            ->setDomain($website ? $website->getDomain()->getDomain() : null)
            ->setReseller($this->isResellerSubscription($subscription))
            ->setServerHostname($this->configuration->hostname)
            ->setPackageName($subscription->getPlanName())
            ->setSuspended(boolval($subscription->getSuspendedBy()))
            ->setIp($website ? implode(', ', $this->getWebsiteIps($website)) : null)
            ->setNameservers($nameservers)
            ->setLocation($location ?? null)
            ->setDebug([
                'website' => $website ? $website->jsonSerialize() : null,
                'subscription' => $subscription->jsonSerialize(),
            ]);
    }

    /**
     * Find the server group of the given Website.
     *
     * @param string|null $serverId
     */
    protected function findServerGroupByServerId(?string $serverId): ?ServerGroup
    {
        if (!$serverId) {
            return null;
        }

        $server = $this->api()->servers()->getServerInfo($serverId);
        foreach ($this->api()->servers()->getServerGroups()->getItems() as $group) {
            if ($group->getId() === $server->getGroupId()) {
                return $group;
            }
        }

        return null;
    }

    protected function getSubscriptionUsage(
        string $customerId,
        ?int $subscriptionId,
        ?string $domain
    ): AccountUsage {
        if (!$subscriptionId) {
            $website = $this->findWebsite($customerId, $subscriptionId, $domain, false);

            if (!$website && !empty($domain)) {
                // deleted domain - try again with no domain name
                $website = $this->findWebsite($customerId, $subscriptionId, null, false);
            }
        }

        $subscription = $this->api()->subscriptions()
            ->getSubscription($customerId, $subscriptionId ?? $website->getSubscriptionId());

        if ($subscription->getStatus() === Status::DELETED) {
            throw $this->errorResult('Subscription terminated', ['subscription' => $subscription->jsonSerialize()]);
        }

        $usage = array_reduce($subscription->getResources(), function (array $usage, UsedResource $resource) {
            switch ($resource->getName()) {
                case ResourceName::DISKSPACE:
                    $diskUsed = $this->bytesToMb($resource->getUsage());
                    $diskLimit = $this->bytesToMb($resource->getTotal());

                    $usage['disk_mb'] = [
                        'used' => $diskUsed,
                        'limit' => $diskLimit,
                        'used_pc' => $diskLimit ? round($diskUsed / $diskLimit * 100, 2) . '%' : null,
                    ];
                    break;
                case ResourceName::TRANSFER:
                    $bandwidthUsed = $this->bytesToMb($resource->getUsage());
                    $bandwidthLimit = $this->bytesToMb($resource->getTotal());

                    $usage['bandwidth_mb'] = [
                        'used' => $bandwidthUsed,
                        'limit' => $bandwidthLimit,
                        'used_pc' => $bandwidthLimit ? round($bandwidthUsed / $bandwidthLimit * 100, 2) . '%' : null,
                    ];
                    break;
                case ResourceName::WEBSITES:
                    $websitesUsed = $resource->getUsage();
                    $websitesLimit = $resource->getTotal();

                    $usage['websites'] = [
                        'used' => $websitesUsed,
                        'limit' => $websitesLimit,
                        'used_pc' => $websitesLimit ? round($websitesUsed / $websitesLimit * 100, 2) . '%' : null,
                    ];
                    break;
                case ResourceName::MAILBOXES:
                    $mailboxesUsed = $resource->getUsage();
                    $mailboxesLimit = $resource->getTotal();

                    $usage['mailboxes'] = [
                        'used' => $mailboxesUsed,
                        'limit' => $mailboxesLimit,
                        'used_pc' => $mailboxesLimit ? round($mailboxesUsed / $mailboxesLimit * 100, 2) . '%' : null,
                    ];
                    break;
            }

            return $usage;
        }, []);

        return AccountUsage::create()
            ->setUsageData($usage)
            ->setResellerUsageData($this->getResellerUsageData($subscription));
    }

    /**
     * Build reseller usage data for the given subscription, or null if it isn't
     * a reseller subscription.
     *
     * Only sub-account counts are reported. The other resources of a reseller
     * subscription are not usage figures in the sense of `ResellerUsageData` -
     * Enhance increments them by the quota *sold* to each customer subscription
     * rather than by what those customers actually consume, and they are already
     * returned as-is in the account usage data.
     */
    protected function getResellerUsageData(Subscription $subscription): ?ResellerUsageData
    {
        if (!$this->isResellerSubscription($subscription)) {
            return null;
        }

        /** @var UsedResource $customers */
        $customers = $this->findSubscriptionResource($subscription, ResourceName::CUSTOMERS);

        $subAccountsUsed = $customers->getUsage();
        $subAccountsLimit = $customers->getTotal();

        return new ResellerUsageData([
            'sub_accounts' => [
                'used' => $subAccountsUsed,
                'limit' => $subAccountsLimit,
                'used_pc' => $subAccountsLimit
                    ? round($subAccountsUsed / $subAccountsLimit * 100, 2) . '%'
                    : null,
            ],
        ]);
    }

    /**
     * Determine whether the given subscription has reseller capabilities.
     */
    protected function isResellerSubscription(Subscription $subscription): bool
    {
        return $this->subscriptionHasAllowance($subscription, self::ALLOWANCE_RESELLER);
    }

    /**
     * Find the named resource of the given subscription, if it has one.
     *
     * @param string $name One of `ResourceName`
     */
    protected function findSubscriptionResource(Subscription $subscription, string $name): ?UsedResource
    {
        foreach ($subscription->getResources() ?? [] as $resource) {
            if ($resource->getName() === $name) {
                return $resource;
            }
        }

        return null;
    }

    /**
     * Determine whether the given subscription has the named allowance.
     *
     * @param string $allowanceName E.g., "allowReselling"
     */
    protected function subscriptionHasAllowance(Subscription $subscription, string $allowanceName): bool
    {
        foreach ($subscription->getAllowances() ?? [] as $allowance) {
            if ($allowance->getName() === $allowanceName) {
                return true;
            }
        }

        return false;
    }

    protected function findWebsite(
        string $customerId,
        ?int $subscriptionId = null,
        ?string $domain = null,
        bool $orFail = true
    ): ?Website {
        if (!$subscriptionId && !$domain) {
            throw $this->errorResult('Website domain name is required without subscription id');
        }

        $result = $this->api()->websites()->getWebsites(
            $customerId,
            null,
            null,
            null,
            null,
            $domain,
            null,
            null,
            $subscriptionId,
            null,
            null,
            null,
            null,
            null,
            'false'
        );

        if (!$result) {
            if (!$orFail) {
                return null;
            }

            throw $this->errorResult('Unable to get customer websites', $this->getLastGuzzleRequestDebug());
        }

        $websites = $result->getItems();

        if (isset($domain)) {
            $websites = array_filter($websites, function (Website $website) use ($domain) {
                return strcasecmp($domain, $website->getDomain()->getDomain()) === 0;
            });

            if (count($websites) !== 1) {
                if (!$orFail) {
                    return null;
                }

                throw $this->errorResult(sprintf('Found %s websites for the given domain', count($websites)), [
                    'customer_id' => $customerId,
                    'subscription_id' => $subscriptionId,
                    'domain' => $domain,
                ]);
            }
        }

        /** @var Website $website */
        if (!$website = Arr::first($websites)) {
            return null;
        }

        // get website again to receive full object including IPs
        return $this->api()->websites()->getWebsite($customerId, $website->getId());
    }

    /**
     * @return string[]
     */
    public function getWebsiteIps(Website $website): array
    {
        if ($website->getServerIps()) {
            return array_map(function (ServerIp $ip) {
                return $ip->getIp();
            }, $website->getServerIps());
        }

        $offset = 0;
        $limit = 10;

        while (true) {
            $servers = $this->api()->servers()->getServers($offset, $limit);

            foreach ($servers->getItems() as $server) {
                if ($website->getAppServerId() === $server->getId()) {
                    return array_map(function (ServerIp $ip) {
                        return $ip->getIp();
                    }, $server->getIps());
                }
            }

            if ($servers->getTotal() <= ($offset + $limit)) {
                break;
            }

            $offset += $limit;
        }

        return []; // IPs unknown
    }

    /**
     * Finds the owner member of the given customer id, preferring the given
     * email if it exists.
     */
    protected function findOwnerMember(string $customerId, ?string $email = null): Member
    {
        $firstMember = null;
        $offset = 0;
        $limit = 10;

        while (true) {
            $members = $this->api()->members()->getMembers(
                $customerId,
                $offset,
                $limit,
                null,
                null,
                Role::OWNER
            );

            foreach ($members->getItems() as $member) {
                if (is_null($email) || $member->getEmail() === $email) {
                    return $member;
                }

                if (is_null($firstMember)) {
                    $firstMember = $member;
                }
            }

            if ($members->getTotal() <= ($offset + $limit)) {
                break;
            }

            $offset += $limit;
        }

        if (is_null($firstMember)) {
            throw $this->errorResult('Customer login not found', [
                'customer_id' => $customerId,
            ]);
        }

        return $firstMember;
    }

    /**
     * Create a new customer org, login and owner membership and return the customer id.
     */
    protected function createCustomer(string $name, string $email, string $password): string
    {
        $newCustomer = (new NewCustomer())
            ->setName($name);
        $customer = $this->api()->customers()
            ->createCustomer($this->configuration->org_id, $newCustomer);

        if (!$customerId = $customer->getId()) {
            throw $this->errorResult('Failed to create new customer', $this->getLastGuzzleRequestDebug() ?? []);
        }

        try {
            $newLogin = (new LoginInfo())
                ->setName($name)
                ->setEmail($email)
                ->setPassword($password);
            $loginId = $this->api()->logins()
                ->createLogin($customerId, $newLogin)
                ->getId();
        } catch (ApiException $e) {
            $errorData = [
                'new_customer_id' => $customerId,
                'email' => $email,
            ];

            try {
                $this->deleteCustomer($customerId);
            } catch (Throwable $deleteException) {
                // ignore
                $errorData['customer_delete'] = [
                    'error' => $deleteException->getMessage(),
                ];
            } finally {
                $errorMessage = 'Failed to create login for new customer';

                $responseData = json_decode($e->getResponseBody() ?? '', true) ?: [];
                if (!empty($responseData['code'])) {
                    $errorMessage = sprintf('%s [%s]', $errorMessage, $responseData['code']);

                    if ($responseData['code'] === 'already_exists') {
                        $errorMessage = 'A customer with this email address already exists';
                    }
                }

                throw $this->handleException(
                    $e,
                    $errorData,
                    [],
                    $errorMessage
                );
            }
        }

        $newMember = (new NewMember())
            ->setLoginId($loginId)
            ->setRoles([
                Role::OWNER,
            ]);
        $this->api()->members()
            ->createMember($customerId, $newMember);

        return $customerId;
    }

    /**
     * Create a new subscription and return the id.
     */
    protected function createSubscription(string $customerId, int $planId, ?string $dedicatedServerId = null): int
    {
        $newSubscription = (new NewSubscription())
            ->setPlanId($planId);

        if ($dedicatedServerId) {
            $newSubscription->setDedicatedServers(new SubscriptionDedicatedServers([
                'app_server_id' => $dedicatedServerId,
                'db_server_id' => $dedicatedServerId,
                'postgresql_server_id' => $dedicatedServerId,
                'email_server_id' => $dedicatedServerId,
            ]));
        }

        return $this->api()->subscriptions()
            ->createCustomerSubscription($this->configuration->org_id, $customerId, $newSubscription)
            ->getId();
    }

    /**
     * Create a new website and return the id.
     */
    protected function createWebsite(
        string $customerId,
        int $subscriptionId,
        string $domain,
        ?string $serverGroupId = null
    ): string {
        $newWebsite = (new NewWebsite())
            ->setSubscriptionId($subscriptionId)
            ->setDomain($domain);

        if ($serverGroupId) {
            $newWebsite->setServerGroupId($serverGroupId);
        }

        return $this->api()->websites()
            ->createWebsite($customerId, $newWebsite)
            ->getId();
    }

    protected function findPlan(string $packageName): Plan
    {
        if (is_numeric($packageName = trim($packageName))) {
            $packageName = intval($packageName);
        }

        $offset = 0;
        $limit = 10;

        while (true) {
            $plans = $this->api()->plans()->getPlans($this->configuration->org_id, $offset, $limit);

            foreach ($plans->getItems() as $plan) {
                if (is_int($packageName) && $packageName === $plan->getId()) {
                    return $plan;
                }

                if (is_string($packageName) && strtolower($packageName) === trim(strtolower($plan->getName()))) {
                    return $plan;
                }
            }

            if ($plans->getTotal() <= ($offset + $limit)) {
                throw $this->errorResult('Plan not found', [
                    'plan' => $packageName,
                ]);
            }

            $offset += $limit;
        }
    }

    protected function getSsoUrl(string $customerId, ?int $subscriptionId = null, ?string $domain = null): string
    {
        if ($website = $this->findWebsite($customerId, $subscriptionId, $domain ?: null, false)) {
            $websiteId = $website->getId();
        }

        if (strtolower((string)$this->configuration->sso_destination) === 'wordpress') {
            $this->requireEnhanceVersion('8.0.0', 'wordpress login');

            if (!$websiteId) {
                throw $this->errorResult('Website not found', [
                    'customer_id' => $customerId,
                    'subscription_id' => $subscriptionId,
                ]);
            }

            return $this->getWordpressLoginUrl($customerId, $websiteId);
        }

        return $this->getEnhanceLoginUrl($customerId, $websiteId ?? null);
    }

    protected function getEnhanceLoginUrl(string $customerId, ?string $websiteId = null): string
    {
        if (!$this->isEnhanceVersion('8.2.0')) {
            // feature not present / not working prior to v8.2.0 - just redirect them to the panel
            return sprintf(
                'https://%s/websites/%s',
                $this->getControlPanelHostname($customerId)
                    ?? $this->configuration->hostname,
                $websiteId ?? null
            );
        }

        $url = $this->api()->members()->getOrgMemberLogin($customerId, $this->findOwnerMember($customerId)->getId());

        return $this->withControlPanelHostname($customerId, json_decode($url) ?? $url);
    }

    /**
     * Hostname to use for control panel URLs, if the org has one.
     */
    protected function getControlPanelHostname(string $orgId): ?string
    {
        if (isset($this->controlPanelHostname)) {
            return $this->controlPanelHostname ?: null;
        }

        $this->controlPanelHostname = $this->findControlPanelDomain($orgId) ?? false;
        return $this->controlPanelHostname ?: null;
    }

    /**
     * Find the domain name of the given org's control panel website, if any.
     */
    protected function findControlPanelDomain(string $orgId): ?string
    {
        $result = $this->api()->websites()->getWebsites(
            $orgId,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            WebsiteKind::CONTROL_PANEL,
            'false'
        );

        foreach ($result ? $result->getItems() : [] as $website) {
            if ($website->getKind() !== WebsiteKind::CONTROL_PANEL) {
                continue; // guard against control panels which ignore the kind filter
            }

            if ($domain = $website->getDomain()->getDomain()) {
                return $domain;
            }
        }

        return null;
    }

    /**
     * Swap the host of the given control panel URL for the org's control panel
     * domain, leaving the rest of the URL intact.
     */
    protected function withControlPanelHostname(string $orgId, string $url): string
    {
        $hostname = $this->getControlPanelHostname($orgId);
        $parts = parse_url($url);

        if ($parts === false || $hostname === null) {
            return $url; // not a URL we can rewrite - leave it be
        }

        if (empty($parts['host'])) {
            // relative url - simply prefix it with the control panel host
            return sprintf('https://%s/%s', $hostname, ltrim($url, '/'));
        }

        if (strcasecmp($parts['host'], $hostname) === 0) {
            return $url;
        }

        return sprintf(
            '%s://%s%s%s%s%s',
            $parts['scheme'] ?? 'https',
            $hostname,
            isset($parts['port']) ? ':' . $parts['port'] : '',
            $parts['path'] ?? '',
            isset($parts['query']) ? '?' . $parts['query'] : '',
            isset($parts['fragment']) ? '#' . $parts['fragment'] : ''
        );
    }

    protected function getWordpressLoginUrl(string $customerId, string $websiteId): string
    {
        $appId = $this->getWordpressAppId($customerId, $websiteId);

        try {
            $wpUser = $this->api()->wordpress()->getDefaultWpSsoUser($customerId, $websiteId, $appId);
        } catch (ApiException $e) {
            if ($e->getCode() !== 404) {
                throw $e;
            }

            $wpUser = $this->api()->wordpress()->getWordpressUsers($customerId, $websiteId, $appId)->getItems()[0];
        }

        $loginUrl = $this->api()->wordpress()->getWordpressUserSsoUrl(
            $customerId,
            $websiteId,
            $appId,
            $wpUser->getId()
        );

        return json_decode($loginUrl) ?? $loginUrl; // in-case it's returned as a JSON string
    }

    protected function getWordpressAppId(string $customerId, string $websiteId): string
    {
        $apps = $this->api()->apps()->getWebsiteApps($customerId, $websiteId);

        foreach ($apps->getItems() as $app) {
            if ($app->getApp() === WebsiteAppKind::WORDPRESS) {
                return $app->getId();
            }
        }

        throw $this->errorResult('Website does not have Wordpress installed', [
            'customer_id' => $customerId,
            'website_id' => $websiteId,
        ]);
    }

    /**
     * Find a server by name or id.
     *
     * @param string $server Server name or id
     * @param bool $orFail Whether or not to throw an exception upon failure
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    protected function findServer(string $server, bool $orFail = true): ?ServerInfo
    {
        if ($this->isUuid($server)) {
            return $this->api()->servers()->getServerInfo($server);
        }

        $offset = 0;
        $limit = 50;

        do {
            $servers = $this->api()->servers()->getServers($offset, $limit);
            $offset += $limit;

            foreach ($servers->getItems() ?? [] as $serverItem) {
                if (strtolower($serverItem->getFriendlyName()) === strtolower($server)) {
                    return $this->api()->servers()->getServerInfo($serverItem->getId());
                }
            }
        } while ($offset < $servers->getTotal());

        if ($orFail) {
            throw $this->errorResult(sprintf('Server "%s" not found', $server));
        }

        return null;
    }

    /**
     * @param string $groupName Server group name or id
     * @param bool $orFail Whether or not to throw an exception upon failure
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    protected function findServerGroup(string $groupName, bool $orFail = true): ?ServerGroup
    {
        // Get the available groups and check the given one exist
        $groups = $this->api()->servers()->getServerGroups();

        /** @var ServerGroup $validGroup */
        foreach ($groups->getItems() ?? [] as $group) {
            if ($group->getId() === $groupName || strtolower($group->getName()) === strtolower($groupName)) {
                /** @var ServerGroup $validGroup */
                return $group;
            }
        }

        if ($orFail) {
            throw $this->errorResult(sprintf('Server group "%s" not found', $groupName));
        }

        return null;
    }

    /**
     * Assert the given ServerGroup has at least one available application server.
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError If group has no application servers
     */
    protected function assertGroupHasApplicationServer(ServerGroup $group): void
    {
        $offset = 0;
        $limit = 50;

        do {
            $servers = $this->api()->servers()->getServers($offset, $limit);
            foreach ($servers->getItems() as $server) {
                if ($server->getGroupId() !== $group->getId()) {
                    continue; // server not in group
                }

                if ($server->getRoles()->getApplication() !== RoleInstallationState::ENABLED) {
                    continue; // server not an application server
                }

                return; // all good
            }

            $offset += $limit;
        } while ($offset < $servers->getTotal());

        $this->errorResult(sprintf('Server group %s has no application servers', $group->getName()));
    }

    /**
     * Delete a customer/org, forcing deletion if this is the master org.
     *
     * @param string $customerId The Enhance org uuid to delete
     */
    protected function deleteCustomer(string $customerId): void
    {
        $force = $this->isMasterOrg() ? 'true' : 'false';
        $this->api()->orgs()->deleteOrg($customerId, $force);
    }

    /**
     * Determine whether the configured org is the master org, rather than a reseller.
     *
     * Every org in Enhance's nested reseller model has a parent org, except the
     * master org at the root of the tree.
     */
    protected function isMasterOrg(?\Upmind\EnhanceSdk\Model\Org $org = null): bool
    {
        if (is_null($org) && isset($this->isMasterOrg)) {
            return $this->isMasterOrg;
        }

        $org ??= $this->api()->orgs()->getOrg($this->configuration->org_id);
        $parentId = $org->getParentId();

        $isMasterOrg = empty($parentId) || $parentId === $org->getId();
        if ($org->getId() === $this->configuration->org_id) {
            $this->isMasterOrg = $isMasterOrg;
        }

        return $isMasterOrg;
    }


    /**
     * Returns a random password 15 chars long containing lower & uppercase alpha,
     * numeric and special characters.
     */
    protected function generateRandomPassword(): string
    {
        return Helper::generateStrictPassword(15, true, true, true);
    }

    /**
     * @param string $string
     */
    protected function isUuid($string): bool
    {
        return boolval(preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', (string)$string));
    }

    protected function bytesToMb(?int $bytes): ?int
    {
        return isset($bytes) ? intval($bytes / 1000 / 1000) : null;
    }

    protected function api(): Api
    {
        if (isset($this->api)) {
            return $this->api;
        }

        $api = new Api($this->configuration);
        $api->setClient(new Client([
            'handler' => $this->getGuzzleHandlerStack(boolval($this->configuration->debug)),
            'headers' => [
                'Authorization' => 'Bearer ' . $this->configuration->access_token,
            ],
            'verify' => !$this->configuration->ignore_ssl_errors,
        ]));

        return $this->api = $api;
    }

    /**
     * @throws ProvisionFunctionError
     * @throws Throwable
     */
    protected function handleException(Throwable $e, array $data = [], array $debug = [], ?string $message = null): void
    {
        if (!isset($data['enhance_meta'])) {
            try {
                $data['enhance_meta'] = $this->getEnhanceMeta();
            } catch (Throwable $metaException) {
                $data['enhance_meta'] = [
                    'error' => $metaException->getMessage(),
                ];
            }
        }

        if ($e instanceof ProvisionFunctionError) {
            throw $e->withData(
                array_merge($e->getData(), $data)
            )->withDebug(
                array_merge($e->getDebug(), $debug)
            );
        }

        if ($e instanceof ApiException) {
            $responseBody = $e->getResponseBody();
            $responseData = is_string($responseBody) ? json_decode($responseBody, true) : $responseBody;

            if (!$e->getCode() && !$e->getResponseBody()) {
                // hmm maybe connection failed
                if (preg_match('/cURL error (\d+): ([^\(]+)/i', $e->getMessage(), $matches)) {
                    $message = sprintf('API Connection Failed [%s]: %s', $matches[1], $matches[2]);
                }
            }

            if (!$message) {
                $message = sprintf('API Request Failed [%s]', $e->getCode());

                if (isset($responseData['message'])) {
                    $message .= ': ' . $responseData['message'];
                } elseif (isset($responseData['code'])) {
                    switch ($responseData['code']) {
                        case 'not_found':
                            $object = $responseData['detail'] ?? 'object';
                            if ($object === 'org') {
                                $object = 'customer';
                            }

                            $message .= sprintf(': %s not found', ucfirst($object));
                            break;
                        case 'already_exists':
                            $message .= sprintf(': %s already exists', ucfirst($responseData['detail']));
                            break;
                    }
                }
            }

            $data = array_merge([
                'response_code' => $e->getCode(),
                'response_data' => $responseData,
                'exception_message' => $e->getMessage(),
            ], $data);

            if (is_null($responseData)) {
                $debug['response_body'] = $responseBody;
            }

            throw $this->errorResult($message, $data, $debug, $e);
        }

        // let the provision system handle this one
        throw $e;
    }

    /**
     * Get a guzzle handler stack which logs requests/responses if provider is
     * an instance of LogsDebugData and $debugLog === true. Requests and responses
     * will also be stored in $this->guzzleHistory.
     */
    protected function getGuzzleHandlerStack(bool $debugLog = false): HandlerStack
    {
        $stack = HandlerStack::create();

        $stack->push(Middleware::history($this->guzzleHistory));

        if (!$debugLog) {
            return $stack;
        }

        // Rewinds HTTP message body seek position after the stream has been read by Logger middleware
        $rewindMessageBody = function (MessageInterface $message) {
            $message->getBody()->rewind();
            return $message;
        };
        // Logs Request/Response HTTP messages
        $logger = Middleware::log(
            $this->getLogger(),
            new MessageFormatter(MessageFormatter::DEBUG . PHP_EOL),
            LogLevel::DEBUG
        );

        $stack->push(Middleware::mapRequest($rewindMessageBody), 'Rewind-Request-Stream-After-Logging');
        $stack->push(Middleware::mapResponse($rewindMessageBody), 'Rewind-Response-Stream-After-Logging');
        $stack->push($logger, 'Logger');

        return $stack;
    }

    /**
     * Returns an assoc array of debug data for the last guzzle request/response
     * for guzzle clients whose stack was obtained from `$this->getGuzzleHandlerStack()`.
     *
     * @return array<array<string[]>>|null
     */
    protected function getLastGuzzleRequestDebug(): ?array
    {
        /** @var Request|null $lastRequest */
        $lastRequest = Arr::last($this->guzzleHistory)['request'] ?? null;
        /** @var Response|null $lastResponse */
        $lastResponse = Arr::last($this->guzzleHistory)['response'] ?? null;

        if (!$lastRequest) {
            return null;
        }

        $debug = [
            'last_request' => [
                'method' => $lastRequest->getMethod(),
                'url' => $lastRequest->getUri()->__toString(),
            ],
            'last_response' => null
        ];

        if ($lastResponse) {
            $debug['last_response'] = [
                'http_code' => $lastResponse->getStatusCode(),
                'body' => Str::limit($lastResponse->getBody()->__toString(), 300),
            ];
        }

        return $debug;
    }
}
