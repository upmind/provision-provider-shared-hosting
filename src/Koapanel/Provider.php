<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\Koapanel;

use DateTime;
use Throwable;
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
use Upmind\ProvisionProviders\SharedHosting\Data\ResellerOptionParams;
use Upmind\ProvisionProviders\SharedHosting\Data\ResellerPrivileges;
use Upmind\ProvisionProviders\SharedHosting\Data\ResellerUsageData;
use Upmind\ProvisionProviders\SharedHosting\Data\SuspendParams;
use Upmind\ProvisionProviders\SharedHosting\Data\UnitsConsumed;
use Upmind\ProvisionProviders\SharedHosting\Data\UsageData;
use Upmind\ProvisionProviders\SharedHosting\Koapanel\Data\Configuration;

/**
 * Koapanel provision provider: hosting accounts (and resellers) on a
 * Koapanel server through its REST API v1.
 *
 * `package_name` is the id or the name of a package of the panel. Resellers
 * (`as_reseller`) get a quota from `reseller_options` (account_limit,
 * diskspace_mb_limit). Creation is idempotent: the username is derived from
 * the domain and the request carries an Idempotency-Key, so a retried
 * create() returns the same account instead of a second one.
 */
class Provider extends Category implements ProviderInterface
{
    protected const PASSWORD_RULE = 'The password must be at least 12 characters long,'
        . ' with at least 5 different characters, and must not contain the username';

    protected Configuration $configuration;
    protected ?Api $api = null;
    /** @var array<string,mixed>|null GET /auth/me of the API key */
    protected ?array $me = null;

    public function __construct(Configuration $configuration)
    {
        $this->configuration = $configuration;
    }

    public static function aboutProvider(): AboutData
    {
        return AboutData::create()
            ->setName('Koapanel')
            ->setDescription('Create and manage Koapanel hosting accounts and resellers using the Koapanel REST API')
            ->setLogoUrl('https://koapanel.app/favicon.svg');
    }

    /**
     * @throws ProvisionFunctionError
     */
    public function create(CreateParams $params): AccountInfo
    {
        $asReseller = (bool) ($params->as_reseller ?? false);
        $domain = $params->domain ? strtolower((string) $params->domain) : null;
        $email = (string) $params->email;

        try {
            $username = $params->username
                ? strtolower((string) $params->username)
                : $this->newUsername($domain ?? (string) strstr($email, '@', true), $email);
            if (!preg_match('/^[a-z0-9][a-z0-9._-]{2,31}$/', $username)) {
                $this->errorResult(
                    'The username must be 3-32 characters: lowercase letters, digits, dot, dash or underscore'
                );
            }

            $password = (string) ($params->password ?? '');
            if ($password === '') {
                $password = self::generatePassword();
            } elseif (!self::passwordOk($password, $username)) {
                $this->errorResult(self::PASSWORD_RULE);
            }

            $withSite = !$asReseller && $domain !== null && ($this->configuration->create_site ?? true);
            if ($withSite && ($owner = $this->siteOwner($domain)) !== null && $owner !== $username) {
                $this->errorResult(
                    'The hosting account could not be created: the domain is already hosted on this server'
                );
            }

            $key = 'upmind-' . substr(hash('sha256', implode('|', [
                $this->configuration->hostname,
                $username,
                $email,
                (string) $domain,
                (string) ($params->customer_id ?? ''),
            ])), 0, 40);
            $body = ['username' => $username, 'email' => $email, 'passwordMode' => 'set', 'password' => $password];

            try {
                if ($asReseller) {
                    $body['quota'] = $this->resellerQuota($params->reseller_options);
                    $this->api()->request('POST', 'resellers', $body, [], $key);
                } else {
                    $body['package'] = $this->packageId((string) $params->package_name);
                    if (($params->owner_username ?? '') !== '' && empty($params->owns_itself)) {
                        $body['owner'] = (string) $params->owner_username;
                    }
                    $this->api()->request('POST', 'accounts', $body, [], $key);
                }
            } catch (ApiError $e) {
                // a retry after a lost answer: the account is already there, for this customer
                if ($e->status !== 400 || !$this->isSameCustomer($username, $email)) {
                    throw $e;
                }
            }

            if ($withSite) {
                $this->createSite($username, $domain);
            }

            return $this->info($username, $domain, 'Account created');
        } catch (Throwable $e) {
            $this->handleException($e, 'The hosting account could not be created');
        }
    }

    /**
     * @throws ProvisionFunctionError
     */
    public function getInfo(AccountUsername $params): AccountInfo
    {
        try {
            return $this->info((string) $params->username, $this->domainOf($params), 'Account info retrieved');
        } catch (Throwable $e) {
            $this->handleException($e, 'The account information could not be retrieved');
        }
    }

    /**
     * @throws ProvisionFunctionError
     */
    public function getUsage(AccountUsername $params): AccountUsage
    {
        try {
            $acc = $this->account((string) $params->username);
            $gbToMb = fn ($gb) => ((int) $gb) > 0 ? ((int) $gb) * 1024 : null; // 0 = unlimited
            $limit = fn ($n) => ((int) $n) > 0 ? (int) $n : null;
            $mb = fn ($bytes) => round(((int) $bytes) / 1048576, 1);

            if (($acc['role'] ?? '') === 'reseller') {
                $totals = (array) ($acc['totals'] ?? []);
                $quota = (array) ($acc['quota'] ?? []);
                $usage = ResellerUsageData::create()
                    ->setDiskMb(UnitsConsumed::create()
                        ->setUsed($mb($totals['diskBytes'] ?? 0))
                        ->setLimit($gbToMb($quota['diskGB'] ?? 0)))
                    ->setSubAccounts(UnitsConsumed::create()
                        ->setUsed((int) ($totals['accounts'] ?? 0))
                        ->setLimit($limit($quota['maxAccounts'] ?? 0)));

                return AccountUsage::create()->setResellerUsageData($usage)->setMessage('Usage data retrieved');
            }

            $used = (array) ($acc['usage'] ?? []);
            $limits = (array) ($acc['limits'] ?? []);
            $usage = UsageData::create()
                ->setDiskMb(UnitsConsumed::create()
                    ->setUsed($mb($used['diskBytes'] ?? 0))
                    ->setLimit($gbToMb($limits['diskGB'] ?? 0)))
                ->setWebsites(UnitsConsumed::create()
                    ->setUsed((int) ($used['sites'] ?? count((array) ($acc['sites'] ?? []))))
                    ->setLimit($limit($limits['maxSites'] ?? 0)));

            return AccountUsage::create()->setUsageData($usage)->setMessage('Usage data retrieved')
                ->setDebug([
                    'databases' => (int) ($used['databases'] ?? 0),
                    'updated_at' => $used['updatedAt'] ?? null,
                ]);
        } catch (Throwable $e) {
            $this->handleException($e, 'The usage data could not be retrieved');
        }
    }

    /**
     * A one-time login link (valid 60 seconds, single use).
     *
     * @throws ProvisionFunctionError
     */
    public function getLoginUrl(GetLoginUrlParams $params): LoginUrl
    {
        try {
            $path = 'accounts/' . Api::seg((string) $params->username) . '/login-link';
            $link = $this->api()->request('POST', $path, ['next' => '/']);
            $expires = null;
            if (!empty($link['expiresAt'])) {
                $expires = (new DateTime((string) $link['expiresAt']))->setTimezone(new \DateTimeZone('UTC'));
            }

            return LoginUrl::create()
                ->setLoginUrl((string) $link['url'])
                ->setExpires($expires)
                ->setMessage('Login URL generated');
        } catch (Throwable $e) {
            $this->handleException($e, 'The login URL could not be generated');
        }
    }

    /**
     * @throws ProvisionFunctionError
     */
    public function changePassword(ChangePasswordParams $params): EmptyResult
    {
        try {
            if (!self::passwordOk((string) $params->password, (string) $params->username)) {
                $this->errorResult(self::PASSWORD_RULE);
            }
            $this->api()->request('POST', 'accounts/' . Api::seg((string) $params->username) . '/password', [
                'mode' => 'set', 'password' => (string) $params->password,
            ]);

            return $this->emptyResult('Password changed');
        } catch (Throwable $e) {
            $this->handleException($e, 'The password could not be changed');
        }
    }

    /**
     * @throws ProvisionFunctionError
     */
    public function changePackage(ChangePackageParams $params): AccountInfo
    {
        try {
            $u = (string) $params->username;
            if (!empty($params->as_reseller)) {
                $quota = $this->resellerQuota($params->reseller_options);
                $this->api()->request('PATCH', 'resellers/' . Api::seg($u), ['quota' => $quota]);
            } else {
                $package = $this->packageId((string) $params->package_name);
                $this->api()->request('PATCH', 'accounts/' . Api::seg($u), ['package' => $package]);
            }

            return $this->info($u, $this->domainOf($params), 'Package changed');
        } catch (Throwable $e) {
            $this->handleException($e, 'The package could not be changed');
        }
    }

    /**
     * @throws ProvisionFunctionError
     */
    public function changePrimaryDomain(ChangePrimaryDomainParams $params): AccountInfo
    {
        $this->errorResult('Operation not supported');
    }

    /**
     * @throws ProvisionFunctionError
     */
    public function suspend(SuspendParams $params): AccountInfo
    {
        try {
            $u = (string) $params->username;
            $this->api()->request('POST', 'accounts/' . Api::seg($u) . '/suspend', [
                'reason' => (string) (($params->reason ?? '') ?: 'Suspended by the billing system'),
            ]);

            return $this->info($u, $this->domainOf($params), 'Account suspended');
        } catch (Throwable $e) {
            $this->handleException($e, 'The account could not be suspended');
        }
    }

    /**
     * @throws ProvisionFunctionError
     */
    public function unSuspend(AccountUsername $params): AccountInfo
    {
        try {
            $u = (string) $params->username;
            $this->api()->request('POST', 'accounts/' . Api::seg($u) . '/unsuspend');

            return $this->info($u, $this->domainOf($params), 'Account unsuspended');
        } catch (Throwable $e) {
            $this->handleException($e, 'The account could not be unsuspended');
        }
    }

    /**
     * Deletes the account with its sites; an account already gone is fine.
     *
     * @throws ProvisionFunctionError
     */
    public function terminate(AccountUsername $params): EmptyResult
    {
        try {
            try {
                $path = 'accounts/' . Api::seg((string) $params->username);
                $this->api()->request('DELETE', $path, null, ['deleteSites' => 'true']);
            } catch (ApiError $e) {
                if ($e->status !== 404) {
                    throw $e;
                }

                return $this->emptyResult('Account already deleted');
            }

            return $this->emptyResult('Account deleted');
        } catch (Throwable $e) {
            $this->handleException($e, 'The account could not be deleted');
        }
    }

    /**
     * Resellers are created as such (create() with as_reseller): an existing
     * hosting account cannot become a reseller.
     *
     * @throws ProvisionFunctionError
     */
    public function grantReseller(GrantResellerParams $params): ResellerPrivileges
    {
        $this->errorResult('Operation not supported');
    }

    /**
     * @throws ProvisionFunctionError
     */
    public function revokeReseller(AccountUsername $params): ResellerPrivileges
    {
        $this->errorResult('Operation not supported');
    }

    // ---------------------------------------------------------------- helpers

    /**
     * @throws ApiError
     */
    protected function info(string $username, ?string $domain, string $message): AccountInfo
    {
        $acc = $this->account($username);
        $me = $this->me();
        $reseller = ($acc['role'] ?? '') === 'reseller';
        $sites = array_values(array_filter((array) ($acc['sites'] ?? []), 'is_string'));
        if ($domain === null || ($sites && !in_array($domain, $sites, true))) {
            $domain = $sites[0] ?? $domain;
        }
        $hostname = (string) ($me['hostname'] ?? '');
        if (!preg_match('/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i', $hostname)) {
            $hostname = $this->configuration->hostname;
        }
        $ip = (string) ($me['serverIP'] ?? '');

        return AccountInfo::create()
            ->setUsername((string) $acc['username'])
            ->setDomain($domain)
            ->setReseller($reseller)
            ->setServerHostname($hostname)
            ->setPackageName($reseller ? 'Reseller' : (string) (($acc['packageName'] ?? '') ?: ($acc['package'] ?? '')))
            ->setSuspended((bool) ($acc['suspended'] ?? false))
            ->setSuspendReason(($acc['suspendReason'] ?? '') !== '' ? (string) $acc['suspendReason'] : null)
            ->setIp(filter_var($ip, FILTER_VALIDATE_IP) ? $ip : null)
            ->setMessage($message);
    }

    /**
     * @param AccountUsername|SuspendParams|ChangePackageParams $params
     */
    protected function domainOf($params): ?string
    {
        return $params->domain ? (string) $params->domain : null;
    }

    /**
     * @return array<string,mixed>
     *
     * @throws ApiError
     */
    protected function account(string $username): array
    {
        return $this->api()->request('GET', 'accounts/' . Api::seg($username));
    }

    /**
     * @return array<string,mixed>
     *
     * @throws ApiError
     */
    protected function me(): array
    {
        return $this->me ??= $this->api()->request('GET', 'auth/me');
    }

    protected function isSameCustomer(string $username, string $email): bool
    {
        try {
            return strcasecmp((string) ($this->account($username)['email'] ?? ''), $email) === 0;
        } catch (ApiError $e) {
            return false;
        }
    }

    /**
     * A username from the domain (all of it, so shop.com and shop.it differ);
     * when taken by another customer, a variant derived from domain and email,
     * so that a retried create() picks the same one again.
     *
     * @throws ApiError
     */
    protected function newUsername(string $base, string $email): string
    {
        $base = (string) preg_replace('/[^a-z0-9]/', '', strtolower($base));
        $base = (string) preg_replace('/^[^a-z]+/', '', $base);
        if (strlen($base) < 3) {
            $base = 'kp' . $base . 'user';
        }
        $candidates = [substr($base, 0, 16)];
        for ($i = 0; $i < 5; $i++) {
            $candidates[] = substr($base, 0, 11) . sprintf('%05d', crc32($base . '|' . $email . '|' . $i) % 100000);
        }
        foreach ($candidates as $u) {
            try {
                $acc = $this->account($u);
            } catch (ApiError $e) {
                if ($e->status === 404) {
                    return $u;
                }
                throw $e;
            }
            if (strcasecmp((string) ($acc['email'] ?? ''), $email) === 0) {
                return $u; // this customer's account: a retry
            }
        }

        $this->errorResult('No free username could be generated: please choose one');
    }

    /**
     * The id of the panel package named (or identified by) $name.
     *
     * @throws ProvisionFunctionError
     * @throws ApiError
     */
    protected function packageId(string $name): string
    {
        $name = trim($name);
        $byName = null;
        $cursor = null;
        do {
            $page = $this->api()->request('GET', 'packages', null, array_filter(['limit' => 100, 'cursor' => $cursor]));
            foreach ((array) ($page['packages'] ?? []) as $p) {
                if ((string) ($p['id'] ?? '') === $name) {
                    return $name;
                }
                if ($byName === null && strcasecmp((string) ($p['name'] ?? ''), $name) === 0) {
                    $byName = (string) $p['id'];
                }
            }
            $cursor = $page['nextCursor'] ?? null;
        } while ($cursor);

        if ($byName === null) {
            $this->errorResult('Package not found', ['package_name' => $name]);
        }

        return $byName;
    }

    /**
     * @return array{maxAccounts:int,diskGB:int,maxSites:int,maxMailboxes:int}
     */
    protected function resellerQuota(?ResellerOptionParams $options): array
    {
        $disk = (int) ($options->diskspace_mb_limit ?? 0);

        return [
            'maxAccounts' => max(0, (int) ($options->account_limit ?? 0)),
            'diskGB' => $disk > 0 ? (int) ceil($disk / 1024) : 0,
            'maxSites' => 0,
            'maxMailboxes' => 0,
        ];
    }

    /**
     * Creates the site of the domain for the account (a retry finds it there).
     *
     * @throws ApiError
     */
    protected function createSite(string $username, string $domain): void
    {
        $body = ['domain' => $domain, 'owner' => $username];
        if ($this->configuration->php_version) {
            $body['phpVersion'] = $this->configuration->php_version;
        }
        try {
            $key = 'upmind-site-' . substr(hash('sha256', $username . '|' . $domain), 0, 40);
            $this->api()->request('POST', 'sites', $body, [], $key);
        } catch (ApiError $e) {
            if ($e->status === 400 || $e->status === 409) {
                try {
                    $site = $this->api()->request('GET', 'sites/' . Api::seg($domain));
                    if (($site['owner'] ?? '') === $username) {
                        return;
                    }
                } catch (ApiError $ignored) {
                }
            }
            throw $e;
        }
    }

    /**
     * The account that owns the site of $domain on the panel (null: none, or
     * not visible to this key).
     *
     * @throws ApiError
     */
    protected function siteOwner(string $domain): ?string
    {
        try {
            return (string) ($this->api()->request('GET', 'sites/' . Api::seg($domain))['owner'] ?? '');
        } catch (ApiError $e) {
            if ($e->status === 404) {
                return null;
            }
            throw $e;
        }
    }

    /** Whether the panel accepts the password (12+ characters, 5 distinct, not the username). */
    public static function passwordOk(string $password, string $username = ''): bool
    {
        $username = strtolower($username);
        if (mb_strlen($password) < 12 || strlen($password) > 1024 || count(array_unique(mb_str_split($password))) < 5) {
            return false;
        }

        return $username === ''
            || !str_contains(strtolower($password), $username)
            || strlen($password) - strlen($username) >= 8;
    }

    public static function generatePassword(): string
    {
        $alphabet = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        $out = '';
        for ($i = 0; $i < 20; $i++) {
            $out .= ($i > 0 && $i % 5 === 0 ? '-' : '') . $alphabet[random_int(0, strlen($alphabet) - 1)];
        }

        return $out;
    }

    /**
     * Turns panel errors into end-user-safe provision errors (the panel's own
     * message, which may be localised, goes to the error data).
     *
     * @return no-return
     *
     * @throws ProvisionFunctionError
     * @throws Throwable
     */
    protected function handleException(Throwable $e, string $message): void
    {
        if ($e instanceof ProvisionFunctionError) {
            throw $e;
        }
        if ($e instanceof ApiError) {
            $reason = match (true) {
                $e->status === 0 => 'the server could not be reached',
                $e->status === 401 => 'the API key was not accepted',
                $e->status === 403 => 'the API key is not allowed to do this',
                $e->status === 404 => 'account not found',
                $e->status === 409 => 'conflict with the current state of the account',
                $e->status === 429 => 'too many requests, try again in a minute',
                $e->status === 400 && $e->field !== null => 'invalid ' . $e->field,
                $e->status >= 500 => 'server error',
                default => 'request refused',
            };

            $this->errorResult($message . ': ' . $reason, [
                'http_code' => $e->status,
                'error_code' => $e->errorCode,
                'field' => $e->field,
                'panel_message' => $e->getMessage(),
            ], ['last_request' => $this->getLastGuzzleRequestDebug()], $e);
        }

        throw $e;
    }

    /**
     * Guzzle handler for the HTTP requests (null = the default cURL handler);
     * tests override it to serve a fake panel.
     */
    protected function httpHandler(): ?callable
    {
        return null;
    }

    protected function api(): Api
    {
        if ($this->api === null) {
            $stack = $this->getGuzzleHandlerStack();
            if (($handler = $this->httpHandler()) !== null) {
                $stack->setHandler($handler);
            }
            $this->api = new Api($this->configuration, $stack);
        }

        return $this->api;
    }
}
