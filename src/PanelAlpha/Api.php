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
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function createService(CreateParams $params, string $userId, string $name): void
    {
        $planId = $params->package_name;

        if (!is_numeric($planId)) {
            $planId = $this->getPlanId($planId);
        }

        $query = [
            "plan_id" => $planId,
        ];

        $serviceId = $this->makeRequest("users/{$userId}/services", $query, "POST")["id"];

        $query = [
            "user_id" => $userId,
            "service_id" => $serviceId,
            "name" => $name,
        ];

        if ($params->domain) {
            $query["domain"] = $params->domain;
        }

        $this->makeRequest("instances", $query, "POST");
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function createUser(CreateParams $params, string $name): array
    {
        // Prep name
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

        if (!isset($result['id'])) {
            throw ProvisionFunctionError::create('Failed to create user')
                ->withData([
                    'name' => $name,
                    'email' => $params->email,
                ]);
        }

        return $result;
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function getAccountData(string $userId, ?string $domain): array
    {
        if (!is_numeric($userId)) {
            $userId = $this->findUserIdByEmail($userId);
        }

        $account = $this->getUserConfig($userId);

        $service = $this->getService($userId, $domain);

        return [
            'username' => $account['name'],
            'domain' => $service["domain"] ?? null,
            'reseller' => false,
            'server_hostname' => $this->configuration->hostname,
            'package_name' => $service["plan_name"] ?? "unknown",
            'suspended' => isset($service["service"]) && $service["service"]["status"] === "suspended",
            'suspend_reason' => null,
            'ip' => $service['host_ip_address'] ?? null,
            'nameservers' => $service["host_nameservers"] ?? [],
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
        $user = $this->makeRequest('users/email', ['email' => $email]);

        if (empty($user) || !isset($user['id'])) {
            throw ProvisionFunctionError::create('User does not exist')
                ->withData([
                    'email' => $email,
                ]);
        }

        return (string) $user['id'];
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    private function getServiceIds($userId): array
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
    private function getService($userId, $domain)
    {
        $services = $this->getInstances($userId);

        if (!$domain) {
            return $services[0];
        }

        foreach ($services as $s) {
            if (isset($s["domain"]) && $s["domain"] === $domain) {
                return $s;
            }
        }

        throw ProvisionFunctionError::create("Domain does not exist")
            ->withData([
                'domain' => $domain,
            ]);

    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function deleteAccount(string $userId): void
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
    public function updatePackage(string $userId, string $packageName, string $domain): void
    {
        if (!is_numeric($userId)) {
            $userId = $this->findUserIdByEmail($userId);
        }

        $service = $this->getService($userId, $domain);

        $planId = $packageName;

        if (!is_numeric($planId)) {
            $planId = $this->getPlanId($planId);
        }

        $serviceId = $service["service"]["id"];

        $query = [
            'plan_id' => $planId,
        ];

        $this->makeRequest("users/{$userId}/services/{$serviceId}/change-plan", $query, "PUT");
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function getAccountUsage(string $userId, ?string $domain): UsageData
    {
        if (!is_numeric($userId)) {
            $userId = $this->findUserIdByEmail($userId);
        }

        $service = $this->getService($userId, $domain);

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
