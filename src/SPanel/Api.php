<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\SPanel;

use GuzzleHttp\Exception\GuzzleException;
use Illuminate\Support\Arr;
use GuzzleHttp\Client;
use Throwable;
use Carbon\Carbon;
use GuzzleHttp\HandlerStack;
use Upmind\ProvisionBase\Helper;
use Illuminate\Support\Str;
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
    ): ?array
    {
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
        if ($response['result'] == 'error') {
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
     * @throws Throwable
     */
    public function getAccountData(string $username): array
    {
        $body = [
            'action' => 'accounts/listaccounts',
            'accountuser' => $username,
        ];

        $response = $this->makeRequest($body);
        $data = $response['data'][0];

        return [
            'username' => $data['user'],
            'domain' => $data['domain'],
            'reseller' => false,
            'server_hostname' => $this->configuration->hostname,
            'package_name' => $data['package'],
            'suspended' => !($data['suspended'] == '0'),
            'ip' => $data['ip'],
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
        $data = $response['data'][0];

        $disk = UnitsConsumed::create()
            ->setUsed(isset($data['disk']) ? ((int)$data['disk']) : null)
            ->setLimit($data['disklimit'] == 'Unlimited' ? null : (int)$data['disklimit']);

        $inodes = UnitsConsumed::create()
            ->setUsed(isset($data['inodes']) ? ((float)$data['inodes']) : null)
            ->setLimit($data['inodeslimit'] === 'Unlimited' ? null : $data['inodeslimit']);

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
