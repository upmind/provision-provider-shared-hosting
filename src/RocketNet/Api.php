<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\RocketNet;

use Illuminate\Support\Arr;
use Upmind\ProvisionBase\Helper;
use GuzzleHttp\Client;
use RuntimeException;
use Illuminate\Support\Str;
use Upmind\ProvisionProviders\SharedHosting\Data\CreateParams;
use Upmind\ProvisionProviders\SharedHosting\Data\UnitsConsumed;
use Upmind\ProvisionProviders\SharedHosting\Data\UsageData;
use Upmind\ProvisionProviders\SharedHosting\RocketNet\Data\Configuration;
use Upmind\ProvisionBase\Exception\ProvisionFunctionError;

class Api
{
    private Configuration $configuration;

    protected Client $client;

    private string $authToken;

    public function __construct(Client $client, Configuration $configuration)
    {
        $this->configuration = $configuration;
        $this->client = $client;
        $this->authToken = $this->getAuthToken();
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function makeRequest(
        string  $command,
        ?array  $body = null,
        ?string $method = 'POST'
    ): ?array
    {
        $requestParams = [];

        if ($command != 'login') {
            $requestParams['headers'] = [
                'Authorization' => 'Bearer ' . $this->authToken,
            ];
        }

        if ($body) {
            $requestParams['json'] = $body;
        }

        $response = $this->client->request($method, '/v1/' . $command, $requestParams);
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
        return $parsedResult;
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \RuntimeException
     */
    public function createAccount(CreateParams $params, string $username, ?string $location): string
    {
        $password = $params->password ?: Helper::generatePassword();

        $body = [
            'name' => $username,
            'location' => (int)$location,
            'admin_username' => $username,
            'admin_password' => $password,
            'admin_email' => $params->email,
            'label' => $username
        ];

        return $this->makeRequest('sites', $body)['result']['domain'];
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \RuntimeException
     */
    public function getAccountData(string $username, ?string $domain): array
    {
        if (!is_numeric($username)) {
            $username = $this->getSiteIDByDomain($domain);
        }

        $site = $this->getSite($username);

        return [
            'username' => (string)$site['id'],
            'domain' => $site["domain"] ?? null,
            'reseller' => false,
            'server_hostname' => $this->configuration->hostname,
            'package_name' => "unknown",
            'suspended' => $site['status'] === 'suspended',
            'suspend_reason' => $site['status'] === 'suspended' ? (string)$site['status_reason'] : null,
            'ip' => $site['ftp_ip_address'] ?? null,
        ];
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \RuntimeException
     */
    public function getSite(string $siteId): array
    {
        return $this->makeRequest("sites/{$siteId}", null, 'GET')['result'];
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \RuntimeException
     */
    private function getSiteIDByDomain(?string $domain): string
    {
        $users = $this->makeRequest('sites', null, 'GET')['result'];
        foreach ($users as $user) {
            if ($user['domain'] === $domain) {
                return (string)$user['id'];
            }
        }

        throw ProvisionFunctionError::create("User does not exist")
            ->withData([
                'domain' => $domain,
            ]);
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \RuntimeException
     */
    public function getAccountUsage(string $username, ?string $domain): UsageData
    {
        if (!is_numeric($username)) {
            $username = $this->getSiteIDByDomain($domain);
        }

        $result = $this->makeRequest("account/usage", null, 'GET')['result'];
        $limits = $result['limits'] ?? [];
        $usage = [];
        foreach ($result['usage'] ?? [] as $item) {
            if (($item['site_id'] ?? null) === (int)$username) {
                $usage = $item;
                break;
            }
        }
        if (!$usage) {
            return new UsageData();
        }

        $disk = UnitsConsumed::create()
            ->setUsed(isset($usage['disk']) ? (int)$usage['disk'] / 1024 : 0)
            ->setLimit($limits['disk'] != 0 ? (int)($limits['disk']) : null);

        $bandwidth = UnitsConsumed::create()
            ->setUsed(isset($usage['bandwidth']) ? (int)$usage['bandwidth'] / 1024 : 0)
            ->setLimit($limits['bandwidth'] != 0 ? (int)($limits['bandwidth']) : null);

        return UsageData::create()
            ->setDiskMb($disk)
            ->setBandwidthMb($bandwidth);
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \RuntimeException
     */
    public function suspendAccount(string $username, ?string $domain): void
    {
        if (!is_numeric($username)) {
            $username = $this->getSiteIDByDomain($domain);
        }

        $this->makeRequest("sites/{$username}/suspend");
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \RuntimeException
     */
    public function unsuspendAccount(string $username, ?string $domain): void
    {
        if (!is_numeric($username)) {
            $username = $this->getSiteIDByDomain($domain);
        }

        $this->makeRequest("sites/{$username}/unsuspend");
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \RuntimeException
     */
    public function deleteAccount(string $username, ?string $domain): void
    {
        if (!is_numeric($username)) {
            $username = $this->getSiteIDByDomain($domain);
        }

        $this->makeRequest("sites/{$username}", null, 'DELETE');
    }


    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \RuntimeException
     */
    public function getLoginUrl(string $username, ?string $domain)
    {
        if (!is_numeric($username)) {
            $username = $this->getSiteIDByDomain($domain);
        }

        return $this->makeRequest("sites/{$username}/wp/login", null, 'GET')['result']['sign_on_url'] ?? null;
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \RuntimeException
     */
    private function getAuthToken(): string
    {
        $body = [
            'username' => $this->configuration->username,
            'password' => $this->configuration->password,
        ];

        return $this->makeRequest('login', $body)['token'];
    }
}
