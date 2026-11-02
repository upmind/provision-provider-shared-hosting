<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\AdminBolt;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\TransferException;
use Psr\Http\Message\ResponseInterface;
use Upmind\ProvisionBase\Provider\Contract\ProviderInterface;
use Upmind\ProvisionBase\Provider\DataSet\AboutData;
use Upmind\ProvisionProviders\SharedHosting\AdminBolt\Data\Configuration;
use Upmind\ProvisionProviders\SharedHosting\Category;
use Upmind\ProvisionProviders\SharedHosting\Data\AccountInfo;
use Upmind\ProvisionProviders\SharedHosting\Data\AccountUsage;
use Upmind\ProvisionProviders\SharedHosting\Data\AccountUsername;
use Upmind\ProvisionProviders\SharedHosting\Data\ChangePackageParams;
use Upmind\ProvisionProviders\SharedHosting\Data\ChangePasswordParams;
use Upmind\ProvisionProviders\SharedHosting\Data\ChangePrimaryDomainParams;
use Upmind\ProvisionProviders\SharedHosting\Data\CreateParams;
use Upmind\ProvisionProviders\SharedHosting\Data\EmptyResult;
use Upmind\ProvisionProviders\SharedHosting\Data\GetLoginUrlParams;
use Upmind\ProvisionProviders\SharedHosting\Data\GrantResellerParams;
use Upmind\ProvisionProviders\SharedHosting\Data\LoginUrl;
use Upmind\ProvisionProviders\SharedHosting\Data\ResellerPrivileges;
use Upmind\ProvisionProviders\SharedHosting\Data\SuspendParams;
use Upmind\ProvisionProviders\SharedHosting\Data\UnitsConsumed;
use Upmind\ProvisionProviders\SharedHosting\Data\UsageData;

/**
 * AdminBolt shared hosting provider.
 *
 * Uses the AdminBolt REST API (X-API-Key / X-API-Secret headers) on the panel
 * port, with either an administrator key (/api) or a reseller key
 * (/api/reseller). Accounts are looked up by their exact username and plans
 * are addressed by their exact name.
 *
 * @link https://docs.adminbolt.com/user-guide/integrations/billing-integration-api.html
 */
class Provider extends Category implements ProviderInterface
{
    protected Configuration $configuration;
    protected Client|null $client = null;

    public function __construct(Configuration $configuration)
    {
        $this->configuration = $configuration;
    }

    /**
     * @inheritDoc
     */
    public static function aboutProvider(): AboutData
    {
        return AboutData::create()
            ->setName('AdminBolt')
            ->setDescription('Create and manage hosting accounts on AdminBolt servers')
            ->setLogoUrl('https://adminbolt.com/icons/logo-adminbolt-dark.svg');
    }

    /**
     * @inheritDoc
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function create(CreateParams $params): AccountInfo
    {
        if ($params->as_reseller) {
            $this->errorResult('Creating reseller accounts is not supported');
        }

        if (!$params->domain) {
            $this->errorResult('A domain name is required to create a hosting account');
        }

        $payload = array_filter([
            'domain' => $params->domain,
            'hosting_plan' => $params->package_name,
            'username' => $params->username,
            'password' => $params->password,
            'email' => $params->email,
        ], fn ($value) => $value !== null && $value !== '');

        $result = $this->apiRequest('POST', 'hosting-accounts', $payload);
        if ($result['status'] !== 201) {
            $this->apiError('Failed to create account', $result);
        }

        $account = $result['body']['hostingAccount'] ?? $result['body'];
        if (!is_array($account) || !isset($account['username'])) {
            $this->apiError('Failed to create account', $result);
        }

        $message = isset($result['body']['warning'])
            ? 'Account created with a warning: ' . $result['body']['warning']
            : 'Account created';

        return $this->accountInfo($account)
            ->setMessage($message);
    }

    /**
     * @inheritDoc
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function getInfo(AccountUsername $params): AccountInfo
    {
        return $this->accountInfo($this->findAccount($params->username))
            ->setMessage('Account info obtained');
    }

    /**
     * @inheritDoc
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function getUsage(AccountUsername $params): AccountUsage
    {
        $account = $this->findAccount($params->username);

        $result = $this->apiRequest('GET', sprintf('hosting-accounts/%s/usage-details', $account['id']));
        $usage = $result['body']['usageDetails'] ?? null;
        if ($result['status'] !== 200 || !is_array($usage)) {
            $this->apiError('Failed to obtain account usage', $result);
        }

        $usageData = UsageData::create()
            ->setDiskMb($this->unitsConsumed(
                $this->megabytes($usage['diskUsage'] ?? null),
                $this->megabytes($usage['totalDiskUsage'] ?? null)
            ))
            ->setBandwidthMb($this->unitsConsumed(
                $this->megabytes($usage['bandwidth'] ?? null),
                $this->megabytes($usage['totalBandwidth'] ?? null)
            ))
            ->setMailboxes($this->unitsConsumed(
                isset($usage['emailAccounts']) ? (int) $usage['emailAccounts'] : null,
                isset($usage['totalEmailAccounts']) ? (int) $usage['totalEmailAccounts'] : null
            ));

        return AccountUsage::create()
            ->setUsageData($usageData)
            ->setMessage('Account usage obtained');
    }

    /**
     * Returns a single-use sign-on URL for the account's control panel. Login
     * tokens are not available, so a URL is returned for either login type.
     *
     * @inheritDoc
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function getLoginUrl(GetLoginUrlParams $params): LoginUrl
    {
        $account = $this->findAccount($params->username);

        $result = $this->apiRequest('POST', sprintf('hosting-accounts/%s/generate-sso-token', $account['id']));
        $url = $result['body']['sso_url'] ?? null;
        if ($result['status'] !== 200 || !is_string($url) || $url === '') {
            $this->apiError('Failed to obtain a login URL', $result);
        }

        // The sign-on link is single-use and valid for 30 minutes.
        return LoginUrl::create()
            ->setLoginUrl($url)
            ->setExpires(new \DateTime('+30 minutes'))
            ->setMessage('Login URL generated');
    }

    /**
     * @inheritDoc
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function changePassword(ChangePasswordParams $params): EmptyResult
    {
        $account = $this->findAccount($params->username);

        $result = $this->apiRequest('POST', sprintf('hosting-accounts/%s/change-password', $account['id']), [
            'password' => $params->password,
        ]);
        if ($result['status'] !== 200) {
            $this->apiError('Failed to change password', $result);
        }

        return $this->emptyResult('Password changed', [], ['response' => $this->redact($result['body'])]);
    }

    /**
     * @inheritDoc
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function changePackage(ChangePackageParams $params): AccountInfo
    {
        $account = $this->findAccount($params->username);

        $result = $this->apiRequest('PUT', sprintf('hosting-accounts/%s', $account['id']), [
            'hosting_plan' => $params->package_name,
        ]);
        if ($result['status'] !== 200 || !is_array($result['body']) || !isset($result['body']['username'])) {
            $this->apiError('Failed to change package', $result);
        }

        return $this->accountInfo($result['body'])
            ->setMessage('Package changed');
    }

    /**
     * @inheritDoc
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function changePrimaryDomain(ChangePrimaryDomainParams $params): AccountInfo
    {
        $this->errorResult('Operation not supported');
    }

    /**
     * @inheritDoc
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function suspend(SuspendParams $params): AccountInfo
    {
        $account = $this->findAccount($params->username);

        if (!$this->isSuspended($account)) {
            $result = $this->apiRequest('POST', sprintf('hosting-accounts/%s/suspend', $account['id']));
            if ($result['status'] !== 200) {
                $this->apiError('Failed to suspend account', $result);
            }
        }

        return $this->accountInfo($this->findAccount($params->username))
            ->setMessage('Account suspended');
    }

    /**
     * @inheritDoc
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function unSuspend(AccountUsername $params): AccountInfo
    {
        $account = $this->findAccount($params->username);

        if ($this->isSuspended($account)) {
            $result = $this->apiRequest('POST', sprintf('hosting-accounts/%s/unsuspend', $account['id']));
            if ($result['status'] !== 200) {
                $this->apiError('Failed to unsuspend account', $result);
            }
        }

        return $this->accountInfo($this->findAccount($params->username))
            ->setMessage('Account unsuspended');
    }

    /**
     * Deletes the account. An account that no longer exists counts as
     * terminated, so a retried termination succeeds.
     *
     * @inheritDoc
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function terminate(AccountUsername $params): EmptyResult
    {
        $account = $this->findAccount($params->username, false);
        if ($account === null) {
            return $this->emptyResult('Account already terminated');
        }

        $result = $this->apiRequest('DELETE', sprintf('hosting-accounts/%s', $account['id']));
        if (!in_array($result['status'], [200, 404], true)) {
            $this->apiError('Failed to terminate account', $result);
        }

        return $this->emptyResult('Account terminated');
    }

    /**
     * @inheritDoc
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function grantReseller(GrantResellerParams $params): ResellerPrivileges
    {
        $this->errorResult('Operation not supported');
    }

    /**
     * @inheritDoc
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function revokeReseller(AccountUsername $params): ResellerPrivileges
    {
        $this->errorResult('Operation not supported');
    }

    /**
     * Find an account by its exact username.
     *
     * @return array<string, mixed>|null Null when the account does not exist and $orFail is false
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    protected function findAccount(string $username, bool $orFail = true): ?array
    {
        $result = $this->apiRequest('GET', 'hosting-accounts', null, ['username' => $username]);
        if ($result['status'] !== 200 || !is_array($result['body'])) {
            $this->apiError('Failed to look up account', $result);
        }

        foreach ($result['body'] as $account) {
            if (is_array($account) && ($account['username'] ?? null) === $username) {
                return $account;
            }
        }

        if ($orFail) {
            $this->errorResult('Account not found', ['username' => $username]);
        }

        return null;
    }

    /**
     * @param array<string, mixed> $account
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    protected function accountInfo(array $account): AccountInfo
    {
        return AccountInfo::create()
            ->setCustomerId(isset($account['id']) ? (string) $account['id'] : null)
            ->setUsername((string) $account['username'])
            ->setDomain($account['domain'] ?? null)
            ->setServerHostname($this->configuration->hostname)
            ->setPackageName($this->planName($account['hosting_plan_id'] ?? null))
            ->setSuspended($this->isSuspended($account))
            ->setReseller(false)
            ->setDebug(['account' => $this->redact($account)]);
    }

    /**
     * @param array<string, mixed> $account
     */
    protected function isSuspended(array $account): bool
    {
        return (bool) ($account['is_suspended'] ?? false);
    }

    /**
     * Account payloads carry the plan id, while Upmind maps packages by the
     * plan name.
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    protected function planName(int|string|null $planId): string
    {
        if ($planId === null || $planId === '') {
            return 'Unknown';
        }

        $result = $this->apiRequest('GET', sprintf('hosting-plans/%s', $planId));
        if ($result['status'] === 200 && isset($result['body']['name'])) {
            return (string) $result['body']['name'];
        }

        return (string) $planId;
    }

    /**
     * A limit of zero means unlimited.
     */
    protected function unitsConsumed(int|float|null $used, int|float|null $limit): ?UnitsConsumed
    {
        if ($used === null) {
            return null;
        }

        return UnitsConsumed::create()
            ->setUsed($used)
            ->setLimit($limit ?: null);
    }

    /**
     * Usage values are numbers of MB; older panel versions return display
     * strings such as "1,024.50 MB".
     */
    protected function megabytes(int|float|string|null $value): ?float
    {
        if ($value === null || $value === '') {
            return null;
        }

        return (float) str_replace([' MB', ','], '', (string) $value);
    }

    /**
     * @param array<string, mixed>|null $json
     * @param array<string, mixed> $query
     *
     * @return array{status: int, body: mixed}
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    protected function apiRequest(string $method, string $path, ?array $json = null, array $query = []): array
    {
        $options = ['http_errors' => false];
        if ($json !== null) {
            $options['json'] = $json;
        }
        if ($query !== []) {
            $options['query'] = $query;
        }

        try {
            $response = $this->client()->request($method, $path, $options);
        } catch (TransferException $e) {
            $this->errorResult('Unable to connect to the hosting server', [], [
                'exception' => get_class($e),
                'error' => $e->getMessage(),
            ], $e);
        }

        return $this->parseResponse($response);
    }

    /**
     * @return array{status: int, body: mixed}
     */
    protected function parseResponse(ResponseInterface $response): array
    {
        return [
            'status' => $response->getStatusCode(),
            'body' => json_decode((string) $response->getBody(), true),
        ];
    }

    /**
     * Fail with a message that is safe to show to the customer. The panel's
     * own message is added for client errors (validation, not found,
     * conflicts); server errors only go to the debug data.
     *
     * @param array{status: int, body: mixed} $result
     *
     * @return no-return
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    protected function apiError(string $message, array $result): void
    {
        $status = $result['status'];
        $body = $result['body'];
        $apiMessage = is_array($body) && is_string($body['message'] ?? null) ? $body['message'] : null;

        if ($status === 401 || $status === 403) {
            $message .= ': authentication with the hosting server failed';
        } elseif ($status === 429) {
            $message .= ': the hosting server is rate limiting requests, try again shortly';
        } elseif ($status >= 400 && $status < 500 && $apiMessage !== null) {
            $message .= ': ' . $apiMessage;
        }

        $this->errorResult($message, ['http_status' => $status], ['response' => $this->redact($body)]);
    }

    /**
     * Remove credentials from a response before it is returned as debug data.
     */
    protected function redact(mixed $data): mixed
    {
        if (!is_array($data)) {
            return $data;
        }

        foreach ($data as $key => $value) {
            if (is_string($key) && preg_match('/password|secret|token|sso_url|key/i', $key)) {
                $data[$key] = '[redacted]';
            } elseif (is_array($value)) {
                $data[$key] = $this->redact($value);
            }
        }

        return $data;
    }

    protected function client(): Client
    {
        $prefix = $this->configuration->use_reseller_api ? 'api/reseller/' : 'api/';

        return $this->client ??= new Client([
            'handler' => $this->getGuzzleHandlerStack(),
            'base_uri' => sprintf(
                'https://%s:%d/%s',
                $this->configuration->hostname,
                $this->configuration->port ?: 8443,
                $prefix
            ),
            'headers' => [
                'X-API-Key' => $this->configuration->api_key,
                'X-API-Secret' => $this->configuration->api_secret,
                'Accept' => 'application/json',
            ],
            'connect_timeout' => 10,
            'timeout' => 120,
            'verify' => !$this->configuration->ignore_ssl_errors,
        ]);
    }
}
