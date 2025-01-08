<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\Webuzo;

use JsonException;
use Upmind\ProvisionBase\Helper;
use GuzzleHttp\Client;
use Upmind\ProvisionProviders\SharedHosting\Data\CreateParams;
use Upmind\ProvisionProviders\SharedHosting\Data\UnitsConsumed;
use Upmind\ProvisionProviders\SharedHosting\Data\UsageData;
use Upmind\ProvisionProviders\SharedHosting\Webuzo\Data\Configuration;
use Upmind\ProvisionBase\Exception\ProvisionFunctionError;

class Api
{
    private Configuration $configuration;
    protected Client $client;

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
        ?string $method = 'POST'
    ): ?array {
        $requestParams = [];

        if ($command === 'sso') {
            $requestParams['query']['loginAs'] = $body['username'];
            $requestParams['query']['noip'] = 1;
        }

        $requestParams['query']['api'] = 'json';
        $requestParams['query']['act'] = $command;

        if ($body) {
            $requestParams['form_params'] = $body;
        }

        if (isset($this->configuration->api_key)) {
            $requestParams['form_params']['apikey'] = $this->configuration->api_key;

            if (isset($this->configuration->username)) {
                $requestParams['form_params']['apiuser'] = $this->configuration->username;
            } else {
                $requestParams['form_params']['apiuser'] = 'root';
            }
        }

        $response = $this->client->request($method, '/index.php', $requestParams);
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

        if ($error = $this->getResponseErrorMessage($parsedResult)) {
            throw ProvisionFunctionError::create($error)
                ->withData([
                    'response' => $response,
                ]);
        }

        return $parsedResult;
    }

    private function getResponseErrorMessage(array $response): ?string
    {
        if (isset($response['error'])) {
            $message = '';
            foreach ($response['error'] as $error) {
                $message .= strip_tags($error) . '; ';
            }
            return $message;
        }

        return null;
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function createAccount(CreateParams $params, string $username, bool $asReseller): void
    {
        $password = $params->password ?: Helper::generatePassword();

        $body = [
            'create_user' => 1,
            'user' => $username,
            'user_passwd' => $password,
            'cnf_user_passwd' => $password,
            'domain' => $params->domain,
            'email' => $params->email,
            'plan' => $params->package_name,
        ];

        $this->makeRequest('add_user', $body);

        if ($asReseller) {
            $this->setReseller($username, 1);
        }
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function getAccountData(string $username): array
    {
        $account = $this->getUserDetails($username);

        return [
            'username' => $username,
            'domain' => $account['domain'] ?? null,
            'reseller' => $account['type'] == 2,
            'server_hostname' => $this->configuration->hostname,
            'package_name' => $account['plan'] != "" ? $account['plan'] : "Unknown",
            'suspended' => $account['status'] === 'suspended',
            'suspend_reason' => $account['suspend_reason'] ?? null,
            'ip' => $account['ip'] ?? null,
        ];
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function getUserDetails(string $username): ?array
    {
        $body = [
            'search' => $username,
        ];

        $response = $this->makeRequest('users', $body);

        foreach ($response['users'] as $name => $account) {
            if ($name === trim($username)) {
                return $account;
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
    public function getAccountUsage(string $username): UsageData
    {
        $account = $this->getUserDetails($username)['resource'];

        $disk = UnitsConsumed::create()
            ->setUsed((int)$account['disk']['used_bytes'] / (1024 * 1024))
            ->setLimit(($account['disk']['limit_bytes'] == 0 || $account['disk']['limit_bytes'] === 'unlimited')
                ? null : (int)$account['disk']['limit_bytes'] / (1024 * 1024));

        $bandwidth = UnitsConsumed::create()
            ->setUsed((int)$account['bandwidth']['used_bytes'] / (1024 * 1024))
            ->setLimit(($account['bandwidth']['limit_bytes'] == 0 || $account['bandwidth']['limit_bytes'] === 'unlimited')
                ? null : (int)$account['bandwidth']['limit_bytes'] / (1024 * 1024));

        $inodes = UnitsConsumed::create()
            ->setUsed((int)$account['inode']['used'])
            ->setLimit($account['inode']['limit'] === 'unlimited'
                ? null : (int)$account['inode']['limit']);

        $mailboxes = UnitsConsumed::create()
            ->setUsed((int)$account['email_account']['used'])
            ->setLimit($account['email_account']['limit'] === 'unlimited'
                ? null : (int)$account['email_account']['limit']);

        return UsageData::create()
            ->setDiskMb($disk)
            ->setBandwidthMb($bandwidth)
            ->setInodes($inodes)
            ->setMailboxes($mailboxes);
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function suspendAccount(string $username): void
    {
        $body = [
            'suspend' => $username
        ];

        $this->makeRequest('users', $body);
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function unsuspendAccount(string $username): void
    {
        $body = [
            'unsuspend' => $username
        ];

        $this->makeRequest('users', $body);
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function deleteAccount(string $username): void
    {
        $body = [
            'delete_user' => $username
        ];

        $this->makeRequest('users', $body);
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function updatePackage(string $username, string $package): void
    {
        $account = $this->getUserDetails($username);

        $body = [
            'edit_user' => 1,
            'user' => $username,
            'user_name' => $username,
            'domain' => $account['domain'],
            'email' => $account['email'],
            'plan' => $package
        ];

        $this->makeRequest('add_user', $body);
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function updatePassword(string $username, string $password): void
    {
        $account = $this->getUserDetails($username);

        $body = [
            'edit_user' => 1,
            'user' => $username,
            'user_name' => $username,
            'domain' => $account['domain'],
            'email' => $account['email'],
            'plan' => $account['plan'],
            'user_passwd' => $password,
            'cnf_user_passwd' => $password
        ];

        $this->makeRequest('add_user', $body);
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function getLoginUrl(string $username): string
    {
        $body = [
            'username' => $username,
        ];

        $response = $this->makeRequest('sso', $body);

        return $response['done']['url'];
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function setReseller(string $username, int $isReseller): void
    {
        $account = $this->getUserDetails($username);

        $body = [
            'edit_user' => 1,
            'user' => $username,
            'user_name' => $username,
            'domain' => $account['domain'],
            'email' => $account['email'],
            'plan' => $account['plan'],
            'reseller' => $isReseller,
        ];

        $this->makeRequest('add_user', $body);
    }
}
