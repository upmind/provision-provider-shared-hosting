<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\SPanel;

use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Client;
use JsonException;
use Throwable;
use GuzzleHttp\HandlerStack;
use Upmind\ProvisionBase\Helper;
use Upmind\ProvisionProviders\SharedHosting\Data\CreateParams;
use Upmind\ProvisionProviders\SharedHosting\Data\UnitsConsumed;
use Upmind\ProvisionProviders\SharedHosting\Data\UsageData;
use Upmind\ProvisionProviders\SharedHosting\SPanel\Data\Configuration;
use Upmind\ProvisionBase\Exception\ProvisionFunctionError;

class Api
{
    private Configuration $configuration;
    protected Client $client;

    public function __construct(Configuration $configuration, ?HandlerStack $handler = null)
    {
        $this->configuration = $configuration;
        $this->client = new Client([
            'base_uri' => sprintf('https://%s', $this->configuration->hostname),
            'headers' => [
                'Accept' => 'application/json',
            ],
            'connect_timeout' => 10,
            'timeout' => 60,
            'http_errors' => true,
            'allow_redirects' => false,
            'handler' => $handler,
        ]);
    }

    /**
     * @throws GuzzleException
     * @throws ProvisionFunctionError
     * @throws \Throwable
     */
    public function makeRequest(
        ?array  $body = null,
        ?string $method = 'POST'
    ): ?array {
        $requestParams = [];

        $body['token'] = $this->configuration->api_token;
        $requestParams['form_params'] = $body;

        $response = $this->client->request($method, '/spanel/api.php', $requestParams);
        $result = $response->getBody()->getContents();

        $response->getBody()->close();

        if ($result === '') {
            return null;
        }

        return $this->parseResponseData($result);

    }

    /**
     * @throws ProvisionFunctionError
     */
    private function parseResponseData(string $response): array
    {
        try {
            $parsedResult = json_decode($response, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $ex) {
            throw ProvisionFunctionError::create('Failed to parse response data', $ex)
                ->withData([
                    'response' => $response,
                ]);
        }

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
        // First check if result is set as error, if not, return null.
        if (!isset($response['result']) || $response['result'] !== 'error') {
            return null;
        }

        // If message is not set while result is error, return a generic error message.
        if (!isset($response['message'])) {
            return 'Unknown error occurred';
        }

        // Handle different types of message
        if (is_string($response['message'])) {
            return $response['message'];
        }

        if (is_array($response['message'])) {
            return implode(', ', $response['message']);
        }

        // Otherwise, return a generic error message.
        return 'Unknown error occurred';
    }

    /**
     * @throws ProvisionFunctionError
     * @throws \RuntimeException|Throwable
     */
    public function createAccount(CreateParams $params, string $username): void
    {
        $password = $params->password ?: Helper::generatePassword();

        $body = [
            'action' => 'accounts/wwwacct',
            'username' => $username,
            'password' => $password,
            'domain' => $params->domain,
            'package' => $params->package_name,
            'permissions' => 'all'
        ];

        $this->makeRequest($body);
    }

    /**
     * @throws ProvisionFunctionError
     * @throws \RuntimeException
     * @throws \Throwable
     */
    public function getAccountData(string $username): array
    {
        $body = [
            'action' => 'accounts/listaccounts',
            'accountuser' => $username,
        ];

        $response = $this->makeRequest($body);

        // First check if we got a valid response.
        if ($response === null || !isset($response['data'])) {
            throw ProvisionFunctionError::create('Empty API Response');
        }

        // Check if data is an array and not empty
        if (!is_array($response['data']) || empty($response['data'])) {
            throw ProvisionFunctionError::create('Account not found');
        }

        $accountData = [];

        foreach($response['data'] as $data) {
            if (isset($data['user']) && $data['user'] === $username) {
                $accountData = $data;
            }
        }

        // If no matching result is found, throw an error
        if (empty($accountData)) {
            throw ProvisionFunctionError::create('Account not found');
        }

        return [
            'username' => $accountData['user'] ?? null,
            'domain' => $accountData['domain'] ?? null,
            'reseller' => false,
            'server_hostname' => $this->configuration->hostname,
            'package_name' => $accountData['package'] ?? null,
            'suspended' => isset($accountData['suspended']) && $accountData['suspended'] !== '0',
            'ip' => $accountData['ip'] ?? null,
        ];
    }


    /**
     * @throws ProvisionFunctionError
     * @throws \RuntimeException|Throwable
     */
    public function getAccountUsage(string $username): UsageData
    {
        $body = [
            'action' => 'accounts/listaccounts',
            'accountuser' => $username,
        ];

        $response = $this->makeRequest($body);

        // First check if we got a valid response.
        if ($response === null || !isset($response['data'])) {
            throw ProvisionFunctionError::create('Empty API Response');
        }

        // Check if data is an array and not empty
        if (!is_array($response['data']) || empty($response['data'])) {
            throw ProvisionFunctionError::create('Account not found');
        }

        $accountData = [];

        foreach($response['data'] as $data) {
            if (isset($data['user']) && $data['user'] === $username) {
                $accountData = $data;
            }
        }

        // If no matching result is found, throw an error
        if (empty($accountData)) {
            throw ProvisionFunctionError::create('Account not found');
        }

        $disk = UnitsConsumed::create()
            ->setUsed(isset($accountData['disk']) ? ((int)$accountData['disk']) : null)
            ->setLimit(isset($accountData['disklimit']) && $accountData['disklimit']=== 'Unlimited'
                ? null
                : (int) $accountData['disklimit']
            );

        $inodes = UnitsConsumed::create()
            ->setUsed(isset($accountData['inodes']) ? ((float) $accountData['inodes']) : null)
            ->setLimit(isset($accountData['inodeslimit']) && $accountData['inodeslimit'] === 'Unlimited'
                ? null
                : (int) $accountData['inodeslimit']
            );

        return UsageData::create()
            ->setDiskMb($disk)
            ->setInodes($inodes);
    }

    /**
     * @throws ProvisionFunctionError
     * @throws \RuntimeException|Throwable
     */
    public function updatePackage(string $username, string $packageName): void
    {
        $body = [
            'action' => 'accounts/changequota',
            'username' => $username,
            'package' => $packageName,
        ];

        $this->makeRequest($body);
    }

    /**
     * @throws ProvisionFunctionError
     * @throws \RuntimeException|Throwable
     */
    public function updatePassword(string $username, string $password): void
    {
        $body = [
            'action' => 'accounts/changeuserpassword',
            'username' => $username,
            'password' => $password
        ];

        $this->makeRequest($body);
    }


    /**
     * @throws ProvisionFunctionError
     * @throws \RuntimeException|Throwable
     */
    public function suspendAccount(string $username, ?string $reason): void
    {

        $body = [
            'action' => 'accounts/suspendaccount',
            'username' => $username,
            'reason' => $reason,
        ];

        $this->makeRequest($body);
    }


    /**
     * @throws ProvisionFunctionError
     * @throws \RuntimeException|Throwable
     */
    public function unsuspendAccount(string $username): void
    {
        $body = [
            'action' => 'accounts/unsuspendaccount',
            'username' => $username,
        ];

        $this->makeRequest($body);
    }


    /**
     * @throws ProvisionFunctionError
     * @throws \RuntimeException|Throwable
     */
    public function deleteAccount(string $username): void
    {
        $body = [
            'action' => 'accounts/terminateaccount',
            'username' => $username,
        ];

        $this->makeRequest($body);
    }
}
