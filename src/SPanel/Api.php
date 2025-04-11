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
        if ($response['result'] === 'error') {
            if (is_string($response['message'])) {
                return $response['message'];
            }

            if (is_array($response['message'])) {
                return implode(', ', $response['message']);
            }
        }

        return null;
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

        $accountData = [];

        foreach($response['data'] as $data) {
            if ($data['user'] === $username) {
                $accountData = $data;
            }
        }

        // If no matching result is found, throw an error
        if (empty($accountData)) {
            throw ProvisionFunctionError::create('Account not found');
        }

        return [
            'username' => $accountData['user'],
            'domain' => $accountData['domain'],
            'reseller' => false,
            'server_hostname' => $this->configuration->hostname,
            'package_name' => $accountData['package'],
            'suspended' => $accountData['suspended'] !== '0',
            'ip' => $accountData['ip'],
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

        $accountData = [];

        foreach($response['data'] as $data) {
            if ($data['user'] === $username) {
                $accountData = $data;
            }
        }

        // If no matching result is found, throw an error
        if (empty($accountData)) {
            throw ProvisionFunctionError::create('Account not found');
        }

        $disk = UnitsConsumed::create()
            ->setUsed(isset($accountData['disk']) ? ((int)$accountData['disk']) : null)
            ->setLimit($accountData['disklimit'] === 'Unlimited' ? null : (int) $accountData['disklimit']);

        $inodes = UnitsConsumed::create()
            ->setUsed(isset($accountData['inodes']) ? ((float) $accountData['inodes']) : null)
            ->setLimit($accountData['inodeslimit'] === 'Unlimited' ? null : $accountData['inodeslimit']);

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
