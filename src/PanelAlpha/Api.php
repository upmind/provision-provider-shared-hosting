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
    public function createAccount(CreateParams $params, string $username): void
    {
        $password = $params->password ?: Helper::generatePassword();

        $planId = $params->package_name;

        if (!is_numeric($planId)) {
            $planId = $this->getPlanID($planId);
        }

        $query = [
            "first_name" => $username,
            "email" => $params->email,
            "password" => $password,
        ];

        $userId = $this->makeRequest("users", $query, "POST")["id"];

        $query = [
            "plan_id" => $planId,
        ];

        $serviceId = $this->makeRequest("users/{$userId}/services", $query, "POST")["id"];

        $query = [
            "user_id" => $userId,
            "service_id" => $serviceId,
            "name" => $username,
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
    public function getAccountData(string $username, ?string $domain): array
    {
        if (!is_numeric($username)) {
            $username = $this->getUserId($username);
        }

        $account = $this->getUserConfig($username);

        $service = $this->getService($username, $domain);

        return [
            'username' => $account['name'],
            'domain' => $service["domain"] ?? null,
            'reseller' => false,
            'server_hostname' => $this->configuration->hostname,
            'package_name' => $service["plan_name"] ?? "unknown",
            'suspended' => isset($service["service"]) && $service["service"]["status"] == "suspended",
            'suspend_reason' => null,
            'ip' => $service['host_ip_address'] ?? null,
            'nameservers' => $service["host_nameservers"] ?? [],
        ];
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function getUserConfig(string $username): array
    {
        return $this->makeRequest("users/{$username}");
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function getInstances(string $username): array
    {
        return $this->makeRequest("users/{$username}/all-instances");
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function suspendAccount(string $username): void
    {
        if (!is_numeric($username)) {
            $username = $this->getUserId($username);
        }

        $services = $this->getServiceIDs($username);

        foreach ($services as $service) {
            $this->makeRequest("users/$username/services/$service/suspend", null, 'PUT');
        }
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function unsuspendAccount(string $username): void
    {
        if (!is_numeric($username)) {
            $username = $this->getUserId($username);
        }

        $services = $this->getServiceIDs($username);

        foreach ($services as $service) {
            $this->makeRequest("users/$username/services/$service/unsuspend", null, 'PUT');
        }
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    private function getServiceIDs($userId): array
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
    private function getUserId($username): string
    {
        $users = $this->makeRequest('users');
        foreach ($users as $user) {
            if ($user['email'] === $username) {
                return (string) $user['id'];

            }
        }

        throw ProvisionFunctionError::create("User does not exist")
            ->withData([
                'username' => $username,
            ]);
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    private function getPlanID($plan)
    {
        $plans = $this->makeRequest("plans");
        foreach ($plans as $p) {
            if (strtolower($p['name']) === strtolower($plan)) {
                return (string)$p['id'];
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
    private function getService($username, $domain)
    {
        $services = $this->getInstances($username);

        if (!$domain) {
            return $services[0];
        }

        foreach ($services as $s) {
            if ($s["domain"] == $domain) {
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
    public function deleteAccount(string $username): void
    {
        if (!is_numeric($username)) {
            $username = $this->getUserId($username);
        }

        $this->makeRequest("users/$username", null, 'DELETE');
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function updatePackage(string $username, string $package_name, string $domain): void
    {
        if (!is_numeric($username)) {
            $username = $this->getUserId($username);
        }

        $service = $this->getService($username, $domain);

        $planId = $package_name;

        if (!is_numeric($planId)) {
            $planId = $this->getPlanID($planId);
        }

        $serviceId = $service["service"]["id"];
        $query = [
            'plan_id' => $planId,
        ];

        $this->makeRequest("users/{$username}/services/{$serviceId}/change-plan", $query, "PUT");
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function getAccountUsage(string $username, ?string $domain): UsageData
    {
        if (!is_numeric($username)) {
            $username = $this->getUserId($username);
        }

        $service = $this->getService($username, $domain);

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
    public function getLoginUrl(string $username): string
    {
        if (!is_numeric($username)) {
            $username = $this->getUserId($username);
        }

        $sso = $this->makeRequest("users/{$username}/sso-token", null, 'POST');

        return "{$sso["url"]}/sso-login?token={$sso["token"]}";
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function updatePassword(string $username, string $password)
    {
        $email = $username;
        if (!is_numeric($username)) {
            $username = $this->getUserId($username);
        }

        $query = [
            'email' => $email,
            'password' => $password,
        ];

        $this->makeRequest("users/{$username}", $query, "PUT");
    }

}
