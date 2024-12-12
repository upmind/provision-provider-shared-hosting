<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\CentosWeb;

use Illuminate\Support\Arr;
use Upmind\ProvisionBase\Helper;
use GuzzleHttp\Client;
use RuntimeException;
use Illuminate\Support\Str;
use Upmind\ProvisionProviders\SharedHosting\Data\CreateParams;
use Upmind\ProvisionProviders\SharedHosting\Data\UnitsConsumed;
use Upmind\ProvisionProviders\SharedHosting\Data\UsageData;
use Upmind\ProvisionProviders\SharedHosting\CentosWeb\Data\Configuration;
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
        ?string $method = 'POST',
    ): ?array
    {
        $requestParams = [];

        if ($body) {
            $requestParams['form_params'] = $body;
        }

        $requestParams['form_params']['key'] = $this->configuration->api_key;

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

        if (!$parsedResult && Str::contains($response, '{"status":"OK"}')) {
            return ['status' => 'OK'];
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
        $status = $response['status'];
        if ($status == 'Error' || (isset($response['msj']) && $response['msj'] === 'no records exist')) {
            return $response['msj'] ?? $response['msl'] ?? 'Unknown error';
        }

        return null;
    }

    public function createAccount(CreateParams $params, string $username, bool $asReseller): void
    {
        $password = $params->password ?: Helper::generatePassword();

        $body = [
            'action' => 'add',
            'domain' => $params->domain,
            'user' => $username,
            'pass' => $password,
            'email' => $params->email,
            'package' => $params->package_name,
            'server_ips' => $params->custom_ip ?? $this->$this->configuration->ip
        ];

        if ($asReseller) {
            $body['reseller'] = 1;
        }

        $this->makeRequest('account', $body);
    }


    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \RuntimeException
     */
    public function getAccountData(string $username, bool $asReseller): array
    {
        $account = $this->getUserDetails($username, $asReseller);

        return [
            'username' => $username,
            'domain' => $account['domain'] ?? null,
            'reseller' => !($account['reseller'] == ""),
            'server_hostname' => $this->configuration->hostname,
            'package_name' => $account['package_name'],
            'suspended' => $account['status'] === 'suspended',
            'suspend_reason' => $account['suspended_reason'] ?? null,
            'ip' => $account['ip_address'] ?? null,
        ];
    }


    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function getUserDetails(string $username, bool $asReseller): ?array
    {
        $body = [
            'action' => 'list',
        ];

        if ($asReseller) {
            $body['reseller'] = 1;
        }

        $response = $this->makeRequest('account', $body);

        foreach ($response['msj'] as $account) {
            if ($account['username'] == trim($username)) {
                return $account;
            }
        }

        throw ProvisionFunctionError::create("User does not exist")
            ->withData([
                'username' => $username,
            ]);
    }


    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \RuntimeException
     */
    public function getAccountUsage(string $username, bool $asReseller): UsageData
    {
        $account = $this->getUserDetails($username, $asReseller);

        $disk = UnitsConsumed::create()
            ->setUsed((int)$account['diskused'])
            ->setLimit($account['disklimit'] != -1 ? (int)$account['disklimit'] : null);

        $bandwidth = UnitsConsumed::create()
            ->setUsed((int)$account['bandwidth'])
            ->setLimit($account['bwlimit'] != -1 ? (int)$account['bwlimit'] : null);

        return UsageData::create()
            ->setDiskMb($disk)
            ->setBandwidthMb($bandwidth);
    }


    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \RuntimeException
     */
    public function suspendAccount(string $username): void
    {
        $body = [
            'action' => 'susp',
            'user' => $username
        ];

        $this->makeRequest('account', $body);
    }


    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \RuntimeException
     */
    public function unsuspendAccount(string $username): void
    {
        $body = [
            'action' => 'unsp',
            'user' => $username
        ];

        $this->makeRequest('account', $body);
    }


    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \RuntimeException
     */
    public function deleteAccount(string $username): void
    {
        $body = [
            'action' => 'del',
            'user' => $username
        ];

        $this->makeRequest('account', $body);
    }


    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \RuntimeException
     */
    public function updatePassword(string $username, string $password): void
    {
        $body = [
            'action' => 'udp',
            'user' => $username,
            'pass' => $password
        ];

        $this->makeRequest('changepass', $body);
    }


    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \RuntimeException
     */
    public function updatePackage(string $username, int $package): void
    {
        $body = [
            'action' => 'udp',
            'user' => $username,
            'package' => $package
        ];

        $this->makeRequest('changepack', $body);
    }


    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \RuntimeException
     */
    public function getLoginUrl(string $username, int $timer)
    {
        $body = [
            'action' => 'list',
            'user' => $username,
            'timer' => $timer
        ];

        return $this->makeRequest('user_session', $body)['msj']['details'][0]['url'];
    }
}
