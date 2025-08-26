<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\PanelAlpha;

use GuzzleHttp\Client;
use Upmind\ProvisionBase\Helper;
use Upmind\ProvisionProviders\SharedHosting\Data\CreateParams;
use Upmind\ProvisionProviders\SharedHosting\Data\UnitsConsumed;
use Upmind\ProvisionProviders\SharedHosting\Data\UsageData;
use Upmind\ProvisionProviders\SharedHosting\PanelAlpha\Data\Configuration;
use Upmind\ProvisionBase\Exception\ProvisionFunctionError;

class Api
{
    protected Client $client;
    private Configuration $configuration;

    public function __construct(Client $client, Configuration $configuration)
    {
        $this->client = $client;
        $this->configuration = $configuration;
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function makeRequest(
        string  $command,
        ?array  $body = null,
        ?string $method = 'GET'
    ): ?array
    {
        $requestParams = [];

        if (isset($body)) {
            switch ($method) {
                case 'POST':
                case 'PUT':
                case 'PATCH':
                case 'DELETE':
                    $requestParams['json'] = $body;
                    break;
                case 'GET':
                    $requestParams['query'] = $body;
                    break;
            }
        }

        $response = $this->client->request($method, "api/admin/{$command}", $requestParams);

        $result = $response->getBody()->getContents();

        $response->getBody()->close();

        if ($result === "") {
            return null;
        }

        return $this->parseResponseData($result);
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    private function parseResponseData(string $response): array
    {
        $parsedResult = json_decode($response, true);

        if (!$parsedResult) {
            throw ProvisionFunctionError::create('Unknown Provider API Error')
                ->withData([
                    'response' => $response,
                ]);
        }

        return $parsedResult["data"] ?? [];
    }

    /**
     * Create a new service for the user and return the service ID.
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function createService(CreateParams $params, string $userId): string
    {
        $planId = $params->package_name;

        if (!is_numeric($planId)) {
            $planId = $this->getPlanId($planId);
        }

        $query = [
            'plan_id' => $planId,
        ];

        $result = $this->makeRequest("users/{$userId}/services", $query, 'POST');

        if (empty($result) || !isset($result['id'])) {
            throw ProvisionFunctionError::create('Failed to create service')
                ->withData([
                    'user_id' => $userId,
                    'plan_id' => $planId,
                ]);
        }

        return (string) $result['id'];
    }

    /**
     * Create a new instance for the user and return the instance ID.
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function createInstance(string $userId, $serviceId, string $domain, string $name): string
    {
        $query = [
            'user_id' => $userId,
            'service_id' => $serviceId,
            'name' => $name,
            'domain' => $domain,
        ];

        $result = $this->makeRequest('instances', $query, 'POST');

        if (empty($result) || !isset($result['id'])) {
            throw ProvisionFunctionError::create('Failed to create instance')
                ->withData([
                    'user_id' => $userId,
                    'service_id' => $serviceId,
                    'name' => $name,
                    'domain' => $domain,
                ]);
        }

        return (string) $result['id'];
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function createUser(CreateParams $params, string $name): array
    {
        // If customer name is provided, use it; otherwise, keep using the existing variable.
        if (!empty($params->customer_name)) {
            $name = (string) $params->customer_name;
        }

        // Split name into first and last name and trim them
        $nameArray = array_map('trim', explode(' ', $name, 2));

        $query = [
            'first_name' => mb_substr($nameArray[0], 0, 255),
            'email' => $params->email,
            'password' => $params->password ?: Helper::generatePassword(),
        ];

        // Set last name if it exists
        if (isset($nameArray[1]) && $nameArray[1] !== '') {
            $query['last_name'] = mb_substr($nameArray[1], 0, 255);
        }

        $result = $this->makeRequest('users', $query, 'POST');

        if (empty($result) || !isset($result['id'])) {
            throw ProvisionFunctionError::create('Failed to create user')
                ->withData([
                    'name' => $name,
                    'customer_name' => $params->customer_name,
                    'email' => $params->email,
                ]);
        }

        return $result;
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function getAccountData(string $userId, ?string $serviceId, ?string $domain): array
    {
        if (!is_numeric($userId)) {
            $userId = $this->findUserIdByEmail($userId);
        }

        $account = $this->getUserConfig($userId);

        // If domain is provided, we will try to get the instance data.
        if ($domain !== null) {
            $instance = $this->getInstance($userId, $domain);

            return [
                'customer_id' => $userId,
                'subscription_id' => $instance['service']['id'] ?? null,
                'username' => $account['email'],
                'domain' => $instance['domain'] ?? null,
                'reseller' => false,
                'server_hostname' => $this->configuration->hostname,
                'package_name' => $instance['plan_name'] ?? 'unknown',
                'suspended' => isset($instance['service']['status']) && $instance['service']['status'] === 'suspended',
                'suspend_reason' => null,
                'ip' => $instance['host_ip_address'] ?? null,
                'nameservers' => $instance['host_nameservers'] ?? [],
            ];
        }

        // Otherwise, we will get the service data.
        $service = $this->getService($userId, $serviceId);

        return [
            'customer_id' => $userId,
            'subscription_id' => $service['id'] ?? null,
            'username' => $account['email'],
            'domain' => null,
            'reseller' => false,
            'server_hostname' => $this->configuration->hostname,
            'package_name' => $service['plan_name'] ?? 'unknown',
            'suspended' => isset($service['status']) && $service['status'] === 'suspended',
            'suspend_reason' => null,
            'ip' => $service['host_ip_address'] ?? null,
            'nameservers' => $service['host_nameservers'] ?? [],
        ];
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function getUserConfig(string $userId): array
    {
        return $this->makeRequest("users/{$userId}");
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function getUserServices(string $userId): array
    {
        return $this->makeRequest("users/{$userId}/services");
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function getInstances(string $userId): array
    {
        return $this->makeRequest("users/{$userId}/all-instances");
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function suspendAccount(string $userId): void
    {
        if (!is_numeric($userId)) {
            $userId = $this->findUserIdByEmail($userId);
        }

        $services = $this->getServiceIds($userId);

        foreach ($services as $service) {
            $this->makeRequest("users/$userId/services/$service/suspend", null, 'PUT');
        }
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function unsuspendAccount(string $userId): void
    {
        if (!is_numeric($userId)) {
            $userId = $this->findUserIdByEmail($userId);
        }

        $services = $this->getServiceIds($userId);

        foreach ($services as $service) {
            $this->makeRequest("users/$userId/services/$service/unsuspend", null, 'PUT');
        }
    }

    /**
     * Find User ID by their email address which is unique in PanelAlpha.
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function findUserIdByEmail(string $email): string
    {
        $result = $this->makeRequest('users/email', ['email' => $email]);

        if (empty($result) || !isset($result['id'])) {
            throw ProvisionFunctionError::create('User does not exist')
                ->withData([
                    'email' => $email,
                ]);
        }

        return (string) $result['id'];
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    private function getServiceIds(string $userId, string $domain): array
    {
        $services = $this->makeRequest("users/$userId/services");
        $ids = [];

        foreach ($services as $service) {
            $ids[] = $service['id'];
        }

        return $ids;
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    private function getPlanId(string $plan): string
    {
        $plans = $this->makeRequest('plans');

        foreach ($plans as $p) {
            if (!isset($p['id'], $p['name'])) {
                continue; // Skip invalid plan results
            }

            if (mb_strtolower($p['name']) === mb_strtolower($plan)) {
                return (string) $p['id'];
            }
        }

        throw ProvisionFunctionError::create("Plan does not exist")
            ->withData([
                'plan' => $plan,
            ]);
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    private function getService(string $userId, ?string $serviceId = null)
    {
        $services = $this->getUserServices($userId);

        if (empty($services)) {
            return [];
        }

        // If no service ID is provided, return the first result.
        if ($serviceId === null) {
            return $services[0];
        }

        foreach ($services as $service) {
            if (isset($service['id']) && $serviceId === (string) $service['id']) {
                return $service;
            }
        }

        throw ProvisionFunctionError::create('User Service not found')
            ->withData([
                'user_id' => $userId,
                'service_id' => $serviceId,
            ]);
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    private function getInstance(string $userId, string $domain): array
    {
        $instances = $this->getInstances($userId);

        foreach ($instances as $instance) {
            if (empty($instance) || !isset($instance['domain'])) {
                continue; // Skip instances without a domain
            }

            if (mb_strtolower($instance['domain']) !== mb_strtolower($domain)) {
                continue; // Skip if the domain does not match
            }

            return $instance;
        }

        throw ProvisionFunctionError::create('User Instance not found for domain')
            ->withData([
                'user_id' => $userId,
                'domain' => $domain,
            ]);
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function deleteAccount(string $userId, string $domain): void
    {
        if (!is_numeric($userId)) {
            $userId = $this->findUserIdByEmail($userId);
        }

        $this->makeRequest("users/$userId", null, 'DELETE');
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function updatePackage(string $userId, string $packageName, ?string $serviceId, ?string $domain): void
    {
        if (!is_numeric($userId)) {
            $userId = $this->findUserIdByEmail($userId);
        }

        // If domain is provided, we will get the service ID from there.
        if ($domain !== null) {
            $service = $this->getService($userId, $domain);
            $serviceId = (string) $service["service"]["id"];
        }

        // If we don't have a service ID by now, we cannot proceed.
        if ($serviceId === null) {
            throw ProvisionFunctionError::create('Service ID or Domain must be provided to change package')
                ->withData([
                    'user_id' => $userId,
                    'package_name' => $packageName,
                    'service_id' => $serviceId,
                    'domain' => $domain,
                ]);
        }

        $planId = $packageName;

        if (!is_numeric($planId)) {
            $planId = $this->getPlanId($planId);
        }

        $query = [
            'plan_id' => $planId,
        ];

        $this->makeRequest("users/{$userId}/services/{$serviceId}/change-plan", $query, "PUT");
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function getAccountUsage(string $userId, ?string $serviceId, ?string $domain): UsageData
    {
        if (!is_numeric($userId)) {
            $userId = $this->findUserIdByEmail($userId);
        }

        // Get the service stats by the domain, otherwise by the service ID.
        if ($domain !== null) {
            $instance = $this->getInstance($userId, $domain);
            $service = $this->getService($userId, (string) $instance['service']['id']);
        } else {
            $service = $this->getService($userId, $serviceId);
        }

        $usage = $service["stats"] ?? null;

        if (!$usage) {
            return new UsageData();
        }

        $disk = UnitsConsumed::create()
            ->setUsed((int)$usage['storage']["usage"] / 1024 / 1024)
            ->setLimit($usage['storage']['maximum'] != 0 ? (int)($usage['storage']['maximum'] / 1024 / 1024) : null);

        $bandwidth = UnitsConsumed::create()
            ->setUsed((int)$usage['bandwidth']["usage"] / 1024 / 1024)
            ->setLimit($usage['bandwidth']['maximum'] != 0 ? (int)($usage['bandwidth']['maximum'] / 1024 / 1024) : null);

        return UsageData::create()
            ->setDiskMb($disk)
            ->setBandwidthMb($bandwidth);
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function getLoginUrl(string $userId): string
    {
        if (!is_numeric($userId)) {
            $userId = $this->findUserIdByEmail($userId);
        }

        $sso = $this->makeRequest("users/{$userId}/sso-token", null, 'POST');

        if (empty($sso) || !isset($sso['url'], $sso['token'])) {
            throw ProvisionFunctionError::create('Failed to get Login URL')
                ->withData([
                    'user_id' => $userId,
                ]);
        }

        return "{$sso["url"]}/sso-login?token={$sso["token"]}";
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function updatePassword(string $userId, string $password): void
    {
        if (!is_numeric($userId)) {
            $userId = $this->findUserIdByEmail($userId);
        }

        $account = $this->getUserConfig($userId);

        if (!isset($account['id'], $account['email'])) {
            throw ProvisionFunctionError::create('User not found')
                ->withData([
                    'user_id' => $userId,
                ]);
        }

        $query = [
            'email' => $account['email'],
            'password' => $password,
        ];

        $this->makeRequest("users/{$userId}", $query, "PUT");
    }
}
