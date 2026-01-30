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
use Upmind\EnhanceSdk\Model\Plan;
use Upmind\EnhanceSdk\Model\ResourceName;
use Upmind\EnhanceSdk\Model\Role;
use Upmind\EnhanceSdk\Model\RoleInstallationState;
use Upmind\EnhanceSdk\Model\ServerGroup;
use Upmind\EnhanceSdk\Model\ServerIp;
use Upmind\EnhanceSdk\Model\Status;
use Upmind\EnhanceSdk\Model\UpdateSubscription;
use Upmind\EnhanceSdk\Model\UsedResource;
use Upmind\EnhanceSdk\Model\Website;
use Upmind\EnhanceSdk\Model\WebsiteAppKind;
use Upmind\ProvisionBase\Exception\ProvisionFunctionError;
use Upmind\ProvisionBase\Helper;
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
use Upmind\ProvisionProviders\SharedHosting\Enhance\Data\Configuration;

class Provider extends Category implements ProviderInterface
{
    /**
     * @var Configuration
     */
    protected $configuration;

    /**
     * @var mixed[]|null
     */
    protected $meta;

    /**
     * @var Api|null
     */
    protected $api;

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

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function create(CreateParams $params): AccountInfo
    {
        try {
            $customerCreated = false;

            $plan = $this->findPlan($params->package_name);

            if ($params->location && !$this->configuration->create_subscription_only) {
                $serverGroupId = $this->findServerGroup(trim($params->location))->getId();
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

            $subscriptionId = $this->createSubscription($customerId, $plan->getId());

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
                    $this->api()->orgs()->deleteOrg($customerId, 'true');
                } catch (Throwable $e) {
                    // ignore
                    $errorData = [
                        'customer_delete' => [
                            'error' => $e->getMessage(),
                        ],
                    ];
                }
            }

            $this->handleException($e, $errorData ?? []);
        }
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function suspend(SuspendParams $params): AccountInfo
    {
        try {
            if (!$params->subscription_id) {
                $this->errorResult('Subscription ID is required');
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
            $this->handleException($e);
        }
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function unSuspend(AccountUsername $params): AccountInfo
    {
        try {
            if (!$params->subscription_id) {
                $this->errorResult('Subscription ID is required');
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
            $this->handleException($e);
        }
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function terminate(AccountUsername $params): EmptyResult
    {
        try {
            if (!$params->subscription_id) {
                $this->errorResult('Subscription ID is required');
            }

            $customerId = $params->customer_id ?: $this->findCustomerIdByEmail($params->username);

            $this->api()->subscriptions()
                ->deleteSubscription($customerId, $params->subscription_id, 'false');

            return $this->emptyResult('Subscription deleted');
        } catch (Throwable $e) {
            $this->handleException($e);
        }
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
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
            $this->handleException($e);
        }
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function getUsage(AccountUsername $params): AccountUsage
    {
        try {
            $customerId = $params->customer_id ?: $this->findCustomerIdByEmail($params->username);
            $subscriptionId = intval($params->subscription_id) ?: null;

            return $this->getSubscriptionUsage($customerId, $subscriptionId, $params->domain);
        } catch (Throwable $e) {
            $this->handleException($e);
        }
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function getLoginUrl(GetLoginUrlParams $params): LoginUrl
    {
        try {
            $customerId = $params->customer_id ?: $this->findCustomerIdByEmail($params->username);
            $subscriptionId = intval($params->subscription_id) ?: null;

            $loginUrl = $this->getSsoUrl($customerId, $subscriptionId, $params->domain);

            return LoginUrl::create()
                ->setLoginUrl($loginUrl);
        } catch (Throwable $e) {
            $this->handleException($e);
        }
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function changePassword(ChangePasswordParams $params): EmptyResult
    {
        try {
            if (!$params->customer_id) {
                $this->errorResult('Customer ID is required');
            }

            $owner = $this->findOwnerMember($params->customer_id, $params->username);

            $this->api()->logins()->startPasswordRecovery(
                ['email' => $owner->getEmail()],
                $params->customer_id
            );

            return $this->emptyResult('Password reset initiated - please check your email');
        } catch (Throwable $e) {
            $this->handleException($e);
        }
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function changePackage(ChangePackageParams $params): AccountInfo
    {
        try {
            if (!$params->subscription_id) {
                $this->errorResult('Subscription ID is required');
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
            $this->handleException($e);
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
        $this->errorResult('Operation not supported');
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function revokeReseller(AccountUsername $params): ResellerPrivileges
    {
        $this->errorResult('Operation not supported');
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
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    protected function requireEnhanceVersion(string $requireVersion, string $operation = 'this operation'): void
    {
        if (!$this->isEnhanceVersion($requireVersion)) {
            $this->errorResult(
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

        return PromiseUtils::all($requests)
            ->then(function ($meta) {
                $this->meta = $meta;
                return $meta;
            })
            ->wait();
    }

    /**
     * @throws \Upmind\EnhanceSdk\ApiException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \InvalidArgumentException
     */
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

        $this->errorResult('Customer not found', ['email' => $email]);
    }

    /**
     * @throws \Upmind\EnhanceSdk\ApiException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \InvalidArgumentException
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

        if ($subscription->getStatus() == Status::DELETED) {
            $this->errorResult('Subscription terminated', ['subscription' => $subscription->jsonSerialize()]);
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

        if ($website) {
            if ($serverGroup = $this->findServerGroupByWebsite($website)) {
                $location = $serverGroup->getName();
            }
        }

        return AccountInfo::create()
            ->setMessage('Subscription info obtained')
            ->setCustomerId($customerId)
            ->setUsername($email ?? $this->findOwnerMember($customerId)->getEmail())
            ->setSubscriptionId($subscription->getId())
            ->setDomain($website ? $website->getDomain()->getDomain() : null)
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
     * @throws \Upmind\EnhanceSdk\ApiException
     * @throws \InvalidArgumentException
     */
    protected function findServerGroupByWebsite(Website $website): ?ServerGroup
    {
        if (!$serverId = $website->getAppServerId()) {
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

    /**
     * @throws \Upmind\EnhanceSdk\ApiException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \InvalidArgumentException
     */
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

        $subscription = $this->api()->subscriptions()->getSubscription(
            $customerId,
            !$subscriptionId ? $website->getSubscriptionId() : $subscriptionId
        );

        if ($subscription->getStatus() == Status::DELETED) {
            $this->errorResult('Subscription terminated', ['subscription' => $subscription->jsonSerialize()]);
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

        return new AccountUsage([
            'usage_data' => $usage,
        ]);
    }

    /**
     * @throws \Upmind\EnhanceSdk\ApiException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    protected function findWebsite(
        string $customerId,
        ?int $subscriptionId = null,
        ?string $domain = null,
        bool $orFail = true
    ): ?Website {
        if (!$subscriptionId && !$domain) {
            $this->errorResult('Website domain name is required without subscription id');
        }

        /** @var false|null|\Upmind\EnhanceSdk\Model\WebsitesListing $result */
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

            $this->errorResult('Unable to get customer websites', $this->getLastGuzzleRequestDebug());
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

                $this->errorResult(sprintf('Found %s websites for the given domain', count($websites)), [
                    'customer_id' => $customerId,
                    'subscription_id' => $subscriptionId,
                    'domain' => $domain,
                ]);
            }
        }

        if (!$website = Arr::first($websites)) {
            return null;
        }

        /** @var Website $website */

        // get website again to receive full object including IPs
        return $this->api()->websites()->getWebsite($customerId, $website->getId());
    }

    /**
     * @return string[]
     *
     * @throws \Upmind\EnhanceSdk\ApiException
     * @throws \InvalidArgumentException
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
     *
     * @throws \Upmind\EnhanceSdk\ApiException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \InvalidArgumentException
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
            $this->errorResult('Customer login not found', [
                'customer_id' => $customerId,
            ]);
        }

        return $firstMember;
    }

    /**
     * Create a new customer org, login and owner membership and return the customer id.
     *
     * @throws \Upmind\EnhanceSdk\ApiException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    protected function createCustomer(string $name, string $email, string $password): string
    {
        $newCustomer = (new NewCustomer())
            ->setName($name);
        $customer = $this->api()->customers()
            ->createCustomer($this->configuration->org_id, $newCustomer);

        if (!$customerId = $customer->getId()) {
            $this->errorResult('Failed to create new customer', $this->getLastGuzzleRequestDebug() ?? []);
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
            try {
                $this->api()->orgs()->deleteOrg($customerId, 'false');
            } finally {
                $errorMessage = 'Failed to create login for new customer';

                $responseData = json_decode($e->getResponseBody() ?? '', true) ?: [];
                if (!empty($responseData['code'])) {
                    $errorMessage = sprintf('%s [%s]', $errorMessage, $responseData['code']);

                    if ($responseData['code'] === 'already_exists') {
                        $errorMessage = 'A customer with this email address already exists';
                    }
                }

                $this->handleException(
                    $e,
                    ['new_customer_id' => $customerId, 'email' => $email],
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
     *
     * @throws \Upmind\EnhanceSdk\ApiException
     * @throws \InvalidArgumentException
     */
    protected function createSubscription(string $customerId, int $planId): int
    {
        $newSubscription = (new NewSubscription())
            ->setPlanId($planId);

        return $this->api()->subscriptions()
            ->createCustomerSubscription($this->configuration->org_id, $customerId, $newSubscription)
            ->getId();
    }

    /**
     * Create a new website and return the id.
     *
     * @throws \Upmind\EnhanceSdk\ApiException
     * @throws \InvalidArgumentException
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

    /**
     * @throws \Upmind\EnhanceSdk\ApiException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \InvalidArgumentException
     */
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
                $this->errorResult('Plan not found', [
                    'plan' => $packageName,
                ]);
            }

            $offset += $limit;
        }
    }

    /**
     * @throws \Upmind\EnhanceSdk\ApiException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    protected function getSsoUrl(string $customerId, ?int $subscriptionId = null, ?string $domain = null): string
    {
        if ($website = $this->findWebsite($customerId, $subscriptionId, $domain ?: null, false)) {
            $websiteId = $website->getId();
        }

        if (strtolower((string)$this->configuration->sso_destination) === 'wordpress') {
            $this->requireEnhanceVersion('8.0.0', 'wordpress login');

            if (!isset($websiteId)) {
                $this->errorResult('Website not found', [
                    'customer_id' => $customerId,
                    'subscription_id' => $subscriptionId,
                ]);
            }

            return $this->getWordpressLoginUrl($customerId, $websiteId);
        }

        return $this->getEnhanceLoginUrl($customerId, $websiteId ?? null);
    }

    /**
     * @throws \Upmind\EnhanceSdk\ApiException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \InvalidArgumentException
     */
    protected function getEnhanceLoginUrl(string $customerId, ?string $websiteId = null): string
    {
        if (!$this->isEnhanceVersion('8.2.0')) {
            // feature not present / not working prior to v8.2.0 - just redirect them to the panel
            return sprintf('https://%s/websites/%s', $this->configuration->hostname, $websiteId ?? null);
        }

        $url = $this->api()->members()->getOrgMemberLogin($customerId, $this->findOwnerMember($customerId)->getId());

        return json_decode($url) ?? $url;
    }

    /**
     * @throws \Upmind\EnhanceSdk\ApiException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \InvalidArgumentException
     */
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

    /**
     * @throws \Upmind\EnhanceSdk\ApiException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \InvalidArgumentException
     */
    protected function getWordpressAppId(string $customerId, string $websiteId): string
    {
        $apps = $this->api()->apps()->getWebsiteApps($customerId, $websiteId);

        foreach ($apps->getItems() as $app) {
            if ($app->getApp() == WebsiteAppKind::WORDPRESS) {
                return $app->getId();
            }
        }

        $this->errorResult('Website does not have Wordpress installed', [
            'customer_id' => $customerId,
            'website_id' => $websiteId,
        ]);
    }

    /**
     * @param string $location Server group name or id
     * @param bool $orFail Whether or not to throw an exception upon failure
     *
     * @throws \Upmind\EnhanceSdk\ApiException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \InvalidArgumentException
     */
    protected function findServerGroup(string $location, bool $orFail = true): ?ServerGroup
    {
        // Get the available groups and check the given one exist
        $groups = $this->api()->servers()->getServerGroups();

        $validGroup = null;
        foreach ($groups->getItems() ?? [] as $group) {
            if ($group->getId() === $location || strtolower($group->getName()) === strtolower($location)) {
                /** @var ServerGroup $validGroup */
                $validGroup = $group;
                break;
            }
        }

        if ($validGroup === null) {
            if ($orFail) {
                $this->errorResult(sprintf('Server group "%s" not found', $location));
            }

            return null;
        }

        // Check the server group has at least one application server assigned
        $servers = $this->api()->servers()->getServers();
        foreach ($servers->getItems() as $server) {
            if ($server->getGroupId() !== $validGroup->getId()) {
                continue; // server not in group
            }

            if ($server->getRoles()->getApplication() != RoleInstallationState::ENABLED) {
                continue; // server not an application server
            }

            return $validGroup;
        }

        if ($orFail) {
            $this->errorResult(sprintf('Server group %s has no application servers', $location));
        }

        return null;
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
            'handler' => $this->getGuzzleHandlerStack(),
            'headers' => [
                'Authorization' => 'Bearer ' . $this->configuration->access_token,
            ],
            'verify' => !$this->configuration->ignore_ssl_errors,
        ]));

        return $this->api = $api;
    }

    /**
     * @return no-return
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
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

            $this->errorResult($message, $data, $debug, $e);
        }

        // let the provision system handle this one
        throw $e;
    }

    /**
     * Get a guzzle handler stack which logs requests/responses. These
     * will also be stored in $this->guzzleHistory.
     *
     * @param bool $debugLog @deprecated To be removed in a future version
     */
    protected function getGuzzleHandlerStack(bool $debugLog = false): HandlerStack
    {
        $stack = HandlerStack::create();

        $stack->push(Middleware::history($this->guzzleHistory));

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
     * @return null|array<string, null|array<string, string|int>>
     * @throws \Throwable
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
