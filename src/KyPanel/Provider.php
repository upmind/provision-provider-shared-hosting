<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\KyPanel;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\RequestException;
use Upmind\ProvisionBase\Exception\ProvisionFunctionError;
use Upmind\ProvisionBase\Provider\Contract\ProviderInterface;
use Upmind\ProvisionBase\Provider\DataSet\AboutData;
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
use Upmind\ProvisionProviders\SharedHosting\KyPanel\Data\Configuration;

/**
 * KyPanel hosting control panel.
 */
class Provider extends Category implements ProviderInterface
{
    protected Configuration $configuration;
    protected Client|null $client = null;

    /** @var array<string,string> username => account id */
    protected array $ids = [];

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
            ->setName('KyPanel')
            ->setDescription('Create and manage hosting accounts on KyPanel servers')
            ->setLogoUrl('https://kypanel.com/apple-touch-icon.png');
    }

    /**
     * @inheritDoc
     */
    public function create(CreateParams $params): AccountInfo
    {
        $domain = strtolower((string) $params->domain);
        if ($domain === '') {
            $this->errorResult('Domain name is required');
        }
        $username = $params->username ? strtolower((string) $params->username) : $this->freeUsername($domain);
        $password = $params->password ?: $this->randomPassword();

        $body = [
            'username' => $username,
            'domain' => $domain,
            'password' => $password,
            'contact_email' => (string) $params->email,
            'package_id' => $this->packageId((string) $params->package_name),
        ];
        if ($params->as_reseller) {
            $body['make_reseller'] = true;
        }

        $res = $this->api('POST', 'accounts', $body);
        $this->wait((string) ($res['job_id'] ?? ''));

        return $this->info($username)->setMessage('Account created');
    }

    /**
     * @inheritDoc
     */
    public function getInfo(AccountUsername $params): AccountInfo
    {
        return $this->info((string) $params->username)->setMessage('Account info retrieved');
    }

    /**
     * @inheritDoc
     */
    public function getUsage(AccountUsername $params): AccountUsage
    {
        $a = $this->account((string) $params->username);

        $usage = UsageData::create()
            ->setDiskMb($this->units($a['disk_used_mb'] ?? null, $a['disk_quota_mb'] ?? null))
            ->setBandwidthMb($this->units($a['bw_used_month_mb'] ?? null, $a['bw_limit_mb'] ?? null));

        return AccountUsage::create()->setUsageData($usage);
    }

    /**
     * @inheritDoc
     */
    public function getLoginUrl(GetLoginUrlParams $params): LoginUrl
    {
        $panel = $params->is_reseller ? 'admin' : 'user';
        $res = $this->api('POST', $this->accountPath((string) $params->username) . '/sso', [
            'panel' => $panel,
        ]);
        if (empty($res['url'])) {
            $this->errorResult('Unable to obtain a login URL', [], ['response' => $res]);
        }

        // the link works once and only for 60 seconds
        return LoginUrl::create()
            ->setLoginUrl((string) $res['url'])
            ->setExpires(new \DateTime('+60 seconds', new \DateTimeZone('UTC')));
    }

    /**
     * @inheritDoc
     */
    public function changePassword(ChangePasswordParams $params): EmptyResult
    {
        $this->api('POST', $this->accountPath((string) $params->username) . '/password', [
            'new_password' => (string) $params->password,
        ]);

        return EmptyResult::create()->setMessage('Password changed');
    }

    /**
     * @inheritDoc
     */
    public function changePackage(ChangePackageParams $params): AccountInfo
    {
        $res = $this->api('PUT', $this->accountPath((string) $params->username) . '/package', [
            'package_id' => $this->packageId((string) $params->package_name),
        ]);
        $this->wait((string) ($res['job_id'] ?? ''));

        return $this->info((string) $params->username)->setMessage('Package changed');
    }

    /**
     * @inheritDoc
     */
    public function changePrimaryDomain(ChangePrimaryDomainParams $params): AccountInfo
    {
        $this->errorResult('Operation not supported');
    }

    /**
     * @inheritDoc
     */
    public function suspend(SuspendParams $params): AccountInfo
    {
        $res = $this->api('POST', $this->accountPath((string) $params->username) . '/suspend', [
            'reason' => $params->reason ?: 'Suspended by billing',
        ]);
        $this->wait((string) ($res['job_id'] ?? ''));

        return $this->info((string) $params->username)->setMessage('Account suspended');
    }

    /**
     * @inheritDoc
     */
    public function unSuspend(AccountUsername $params): AccountInfo
    {
        $res = $this->api('POST', $this->accountPath((string) $params->username) . '/unsuspend', (object) []);
        $this->wait((string) ($res['job_id'] ?? ''));

        return $this->info((string) $params->username)->setMessage('Account unsuspended');
    }

    /**
     * @inheritDoc
     */
    public function terminate(AccountUsername $params): EmptyResult
    {
        $username = strtolower((string) $params->username);
        $res = $this->api('DELETE', $this->accountPath($username), null, ['confirm' => $username]);
        $this->wait((string) ($res['job_id'] ?? ''));

        return EmptyResult::create()->setMessage('Account deleted');
    }

    /**
     * @inheritDoc
     */
    public function grantReseller(GrantResellerParams $params): ResellerPrivileges
    {
        return $this->setReseller((string) $params->username, true);
    }

    /**
     * @inheritDoc
     */
    public function revokeReseller(AccountUsername $params): ResellerPrivileges
    {
        return $this->setReseller((string) $params->username, false);
    }

    protected function setReseller(string $username, bool $enabled): ResellerPrivileges
    {
        $res = $this->api('PUT', $this->accountPath($username) . '/reseller', [
            'make_reseller' => $enabled,
        ]);

        return ResellerPrivileges::create()
            ->setReseller((bool) ($res['is_reseller'] ?? $enabled))
            ->setMessage($enabled ? 'Reseller privileges granted' : 'Reseller privileges revoked');
    }

    protected function info(string $username): AccountInfo
    {
        $a = $this->account($username);

        return AccountInfo::create()
            ->setUsername((string) $a['username'])
            ->setDomain($a['main_domain'] ?? null)
            ->setServerHostname($this->configuration->hostname)
            ->setPackageName((string) ($a['package_name'] ?? ''))
            ->setReseller(isset($a['is_reseller']) ? (bool) $a['is_reseller'] : null)
            ->setSuspended(($a['status'] ?? '') === 'suspended')
            ->setSuspendReason($a['suspend_reason'] ?? null)
            ->setIp($a['ip_address'] ?? null);
    }

    protected function account(string $username): array
    {
        return $this->api('GET', $this->accountPath($username));
    }

    protected function accountId(string $username): string
    {
        $username = strtolower(trim($username));
        if (isset($this->ids[$username])) {
            return $this->ids[$username];
        }
        $page = $this->api('GET', 'accounts', null, ['q' => $username, 'page' => 1, 'per_page' => 100]);
        foreach ($page['items'] ?? [] as $a) {
            if (strtolower((string) ($a['username'] ?? '')) === $username) {
                return $this->ids[$username] = (string) $a['id'];
            }
        }
        $this->errorResult('Account not found', ['username' => $username]);
    }

    protected function accountExists(string $username): bool
    {
        try {
            $this->accountId($username);

            return true;
        } catch (ProvisionFunctionError $e) {
            return false;
        }
    }

    // accepts the package name or id
    protected function packageId(string $nameOrId): string
    {
        $want = trim($nameOrId);
        $names = [];
        foreach ($this->api('GET', 'packages')['items'] ?? [] as $p) {
            if ($p['id'] === $want || strcasecmp((string) $p['name'], $want) === 0) {
                return (string) $p['id'];
            }
            $names[] = $p['name'];
        }
        $this->errorResult('Package not found', ['package_name' => $want, 'available' => $names]);
    }

    // usernames: a letter, then letters or digits, 16 max
    protected function freeUsername(string $domain): string
    {
        $base = ltrim((string) preg_replace('/[^a-z0-9]/', '', $domain), '0123456789');
        $base = substr($base !== '' ? $base : 'user', 0, 8);
        if (!$this->accountExists($base)) {
            return $base;
        }
        for ($i = 1; $i < 1000; $i++) {
            $name = substr($base, 0, 8 - strlen((string) $i)) . $i;
            if (!$this->accountExists($name)) {
                return $name;
            }
        }
        $this->errorResult('Unable to find a free username');
    }

    protected function randomPassword(int $length = 16): string
    {
        $pool = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        $out = '';
        for ($i = 0; $i < $length; $i++) {
            $out .= $pool[random_int(0, strlen($pool) - 1)];
        }

        return $out;
    }

    protected function units($used, $limit): UnitsConsumed
    {
        $limit = $limit !== null && (int) $limit > 0 ? (int) $limit : null;

        return UnitsConsumed::create()
            ->setUsed($used === null ? null : (int) $used)
            ->setLimit($limit)
            ->setUsedPc($limit ? round(((int) $used / $limit) * 100, 1) . '%' : null);
    }

    // create/suspend/terminate run as jobs on the server, poll until done
    protected function wait(string $jobId, int $seconds = 240): void
    {
        if ($jobId === '') {
            return;
        }
        $until = time() + $seconds;
        $delay = 1;
        do {
            $job = $this->api('GET', 'jobs/' . rawurlencode($jobId))['job'] ?? [];
            $status = $job['status'] ?? '';
            if ($status === 'succeeded') {
                return;
            }
            if (in_array($status, ['failed', 'canceled', 'cancelled'], true)) {
                $this->errorResult((string) ($job['error'] ?? 'The operation failed'), ['job_id' => $jobId]);
            }
            sleep($delay);
            $delay = min($delay + 1, 5);
        } while (time() < $until);
        $this->errorResult('The operation is still running on the server, check again shortly', ['job_id' => $jobId]);
    }

    /**
     * @throws ProvisionFunctionError
     */
    protected function api(string $method, string $path, $body = null, array $query = []): array
    {
        $options = [];
        if ($body !== null) {
            $options['json'] = $body;
        }
        if ($query) {
            $options['query'] = $query;
        }

        try {
            $response = $this->client()->request($method, $path, $options);
            $data = json_decode((string) $response->getBody(), true);

            return is_array($data) ? $data : [];
        } catch (ConnectException $e) {
            $this->errorResult('Unable to connect to the server', [], [], $e);
        } catch (RequestException $e) {
            $problem = $e->hasResponse() ? json_decode((string) $e->getResponse()->getBody(), true) : null;
            if (is_array($problem) && !empty($problem['title'])) {
                $message = (string) $problem['title'];
                if (!empty($problem['detail'])) {
                    $message .= ': ' . $problem['detail'];
                }
                $this->errorResult($message, ['fields' => $problem['fields'] ?? null], ['response' => $problem], $e);
            }
            throw $e;
        }
    }

    protected function client(): Client
    {
        return $this->client ??= new Client([
            'handler' => $this->getGuzzleHandlerStack(),
            'base_uri' => sprintf(
                'https://%s:%d/api/v1/',
                $this->configuration->hostname,
                $this->configuration->port ?: 7711
            ),
            'headers' => [
                'Authorization' => 'Bearer ' . $this->configuration->api_token,
                'Accept' => 'application/json',
            ],
            'connect_timeout' => 10,
            'timeout' => 60,
            'verify' => $this->configuration->ssl_verify ?? true,
        ]);
    }
}
