<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\CyberPanel;

use GuzzleHttp\Client;
use Upmind\ProvisionBase\Helper;
use Upmind\ProvisionBase\Provider\Contract\ProviderInterface;
use Upmind\ProvisionBase\Provider\DataSet\AboutData;
use Upmind\ProvisionProviders\SharedHosting\Category;
use Upmind\ProvisionProviders\SharedHosting\CyberPanel\Data\Configuration;
use Upmind\ProvisionProviders\SharedHosting\Data\ChangePrimaryDomainParams;
use Upmind\ProvisionProviders\SharedHosting\Data\CreateParams;
use Upmind\ProvisionProviders\SharedHosting\Data\AccountInfo;
use Upmind\ProvisionProviders\SharedHosting\Data\AccountUsage;
use Upmind\ProvisionProviders\SharedHosting\Data\AccountUsername;
use Upmind\ProvisionProviders\SharedHosting\Data\ChangePackageParams;
use Upmind\ProvisionProviders\SharedHosting\Data\ChangePasswordParams;
use Upmind\ProvisionProviders\SharedHosting\Data\EmptyResult;
use Upmind\ProvisionProviders\SharedHosting\Data\GetLoginUrlParams;
use Upmind\ProvisionProviders\SharedHosting\Data\GrantResellerParams;
use Upmind\ProvisionProviders\SharedHosting\Data\LoginUrl;
use Upmind\ProvisionProviders\SharedHosting\Data\ResellerPrivileges;
use Upmind\ProvisionProviders\SharedHosting\Data\SuspendParams;

/**
 * CyberPanel provision provider.
 *
 * CyberPanel's cloud API is domain-centric (websites are identified by their
 * domain name) and fairly limited: there is no endpoint to read a website's
 * package, suspension state or resource usage. As a result getInfo() can only
 * confirm an account exists, and getUsage() is not supported.
 */
class Provider extends Category implements ProviderInterface
{
    private const MIN_USERNAME_LENGTH = 3;
    private const MAX_USERNAME_LENGTH = 8;

    /**
     * Seconds to wait after deleting a website before deleting its owner account.
     */
    private const WEBSITE_DELETION_DELAY = 2;

    /**
     * Placeholder package name for responses where the API cannot report the
     * account's real package (see class docblock).
     */
    private const UNKNOWN_PACKAGE = 'Hosting Account';

    private Configuration $configuration;
    private ?Api $api = null;

    /**
     * Characters allowed in usernames and passwords: alphanumerics,
     * underscore, plus and dash, avoiding those CyberPanel's API rejects in input: ` $ & ( ) [ ] { } ; : ' < >
     *
     * The dash must stay last, as Helper::generatePassword() reads `x-y` as a range,
     * and it must be literal in the sanitisation regex character class.
     *
     * @var string
     */
    private string $allowedCharacters = '0-9a-zA-Z_+-';

    public function __construct(Configuration $configuration)
    {
        $this->configuration = $configuration;
    }

    public static function aboutProvider(): AboutData
    {
        return AboutData::create()
            ->setName('CyberPanel')
            ->setDescription('Create and manage CyberPanel accounts using the CyberPanel API')
            ->setLogoUrl('https://api.upmind.io/images/logos/provision/cyber-panel-logo.svg');
    }

    /**
     * Create a website and its owner account.
     *
     * CyberPanel allows 1 website per username account created this way, so
     * each hosting account maps to a single website (domain).
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function create(CreateParams $params): AccountInfo
    {
        if (!$params->domain) {
            $this->errorResult('Domain name is required');
        }

        if (!$params->package_name) {
            $this->errorResult('Package name is required');
        }

        $username = $params->username ?: $this->sanitize($this->generateUsername($params->domain));
        $password = $params->password
            ? $this->sanitize($params->password)
            : Helper::generatePassword(15, $this->allowedCharacters);

        $this->api()->assertPackageExists($params->package_name);

        $this->api()->createAccount($params, $username, $password);

        return AccountInfo::create()
            ->setUsername($username)
            ->setDomain($params->domain)
            ->setPackageName($params->package_name)
            ->setSuspended(false)
            ->setReseller(false)
            ->setServerHostname($this->configuration->hostname)
            ->setMessage('Account created');
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function getInfo(AccountUsername $params): AccountInfo
    {
        $this->api()->assertAccountExists($params->username);

        // The API cannot report the account's package or suspension state, so
        // these are returned as best-effort defaults.
        $info = AccountInfo::create()
            ->setUsername($params->username)
            ->setServerHostname($this->configuration->hostname)
            ->setPackageName(self::UNKNOWN_PACKAGE)
            ->setSuspended(false)
            ->setReseller(false)
            ->setMessage('Account info retrieved; package and suspension state are not exposed by the hosting API');

        if ($params->domain) {
            $info->setDomain($params->domain);
        }

        return $info;
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function getUsage(AccountUsername $params): AccountUsage
    {
        // The hosting API does not expose per-account resource usage.
        $this->errorResult('Operation not supported');
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function getLoginUrl(GetLoginUrlParams $params): LoginUrl
    {
        $password = $params->current_password;

        // If the password has not been provided, or contains characters CyberPanel
        // rejects, change the password to a random one.
        if (empty($password) || !$this->isValidPassword($password)) {
            $password = Helper::generatePassword(15, $this->allowedCharacters);

            $this->api()->updatePassword($params->username, $password);
        }

        // CyberPanel does not provide a single sign-on token via its public API,
        // so return the control panel URL with the account credentials for a
        // manual login.
        return LoginUrl::create()
            ->setLoginUrl($this->controlPanelUrl())
            ->setForIp($params->user_ip)
            ->setExpires(null)
            ->setPostFields([
                'username' => $params->username,
                'password' => $password,
            ])
            ->setMessage('Manual login required');
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function changePassword(ChangePasswordParams $params): EmptyResult
    {
        if (!$this->isValidPassword($params->password)) {
            $this->errorResult(
                'Password may only contain letters, numbers, underscore (_), plus (+) and dash (-)'
            );
        }

        $this->api()->updatePassword($params->username, $params->password);

        return EmptyResult::create()->setMessage('Password changed');
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function changePackage(ChangePackageParams $params): AccountInfo
    {
        $domain = $this->requireDomain($params->domain);

        if (!$params->package_name) {
            $this->errorResult('Package name is required');
        }

        $this->api()->assertPackageExists($params->package_name);

        $this->api()->updatePackage($domain, $params->package_name);

        return AccountInfo::create()
            ->setUsername($params->username)
            ->setDomain($domain)
            ->setPackageName($params->package_name)
            ->setSuspended(false)
            ->setReseller(false)
            ->setServerHostname($this->configuration->hostname)
            ->setMessage('Package changed');
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function changePrimaryDomain(ChangePrimaryDomainParams $params): AccountInfo
    {
        $this->errorResult('Operation not supported');
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function suspend(SuspendParams $params): AccountInfo
    {
        $domain = $this->requireDomain($params->domain);

        $this->api()->setWebsiteStatus($domain, 'Suspend');

        return AccountInfo::create()
            ->setUsername($params->username)
            ->setDomain($domain)
            ->setPackageName(self::UNKNOWN_PACKAGE)
            ->setSuspended(true)
            ->setSuspendReason($params->reason)
            ->setReseller(false)
            ->setServerHostname($this->configuration->hostname)
            ->setMessage('Account suspended');
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function unSuspend(AccountUsername $params): AccountInfo
    {
        $domain = $this->requireDomain($params->domain);

        $this->api()->setWebsiteStatus($domain, 'Activate');

        return AccountInfo::create()
            ->setUsername($params->username)
            ->setDomain($domain)
            ->setPackageName(self::UNKNOWN_PACKAGE)
            ->setSuspended(false)
            ->setReseller(false)
            ->setServerHostname($this->configuration->hostname)
            ->setMessage('Account unsuspended');
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function terminate(AccountUsername $params): EmptyResult
    {
        // Each user account created by the library owns a single website. Delete it first, then the account.
        if ($params->domain) {
            $this->api()->deleteWebsite($params->domain);

            // Give the panel time to finish removing the website before deleting the account,
            // as unexpected foreign key errors might occur.
            $this->wait(self::WEBSITE_DELETION_DELAY);
        }

        $this->api()->deleteAccount($params->username);

        return EmptyResult::create()->setMessage('Account deleted');
    }

    /**
     * @inheritDoc
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function grantReseller(GrantResellerParams $params): ResellerPrivileges
    {
        // Reseller privilege management is not exposed via the CyberPanel API.
        $this->errorResult('Operation not supported');
    }

    /**
     * @inheritDoc
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function revokeReseller(AccountUsername $params): ResellerPrivileges
    {
        // Reseller privilege management is not exposed via the CyberPanel API.
        $this->errorResult('Operation not supported');
    }

    /**
     * Ensure a domain name is present for domain-centric operations.
     *
     * @return string The validated domain name
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    protected function requireDomain(?string $domain): string
    {
        if (empty($domain)) {
            $this->errorResult('Domain name is required for this operation');
        }

        return $domain;
    }

    /**
     * Build the control panel base URL from the configured hostname/port.
     */
    protected function controlPanelUrl(): string
    {
        $url = $this->configuration->hasPort()
            ? sprintf('https://%s:%s', $this->configuration->getHostname(), $this->configuration->getPort())
            : sprintf('https://%s', $this->configuration->getHostname());

        return rtrim($url, '/') . '/';
    }

    /**
     * Generate a control-panel-safe username from a domain name.
     *
     * Pads the prefix with random lowercase letters when the domain yields too
     * few characters to reach the minimum username length.
     */
    protected function generateUsername(string $base): string
    {
        $prefix = mb_substr(
            preg_replace('/^[^a-z]+/', '', preg_replace('/[^a-z0-9]/', '', strtolower($base))),
            0,
            self::MAX_USERNAME_LENGTH - 2
        );
        $suffix = (string) random_int(1, 99);

        while (strlen($prefix . $suffix) < self::MIN_USERNAME_LENGTH) {
            $prefix .= chr(random_int(ord('a'), ord('z')));
        }

        return $prefix . $suffix;
    }

    /**
     * Whether the password contains only allowed characters.
     */
    protected function isValidPassword(string $password): bool
    {
        return (bool) preg_match('/^[' . $this->allowedCharacters . ']+$/D', $password);
    }

    /**
     * Replace each character not allowed in a username or password with a random digit.
     *
     * Matches per multibyte character where possible, falling back to per byte
     * for input that is not valid UTF-8.
     */
    protected function sanitize(string $value): string
    {
        $replaceWithDigit = static function (): string {
            return (string) random_int(0, 9);
        };

        $disallowedCharactersRegex = '/[^' . $this->allowedCharacters . ']/';

        return preg_replace_callback($disallowedCharactersRegex . 'u', $replaceWithDigit, $value)
            ?? preg_replace_callback($disallowedCharactersRegex, $replaceWithDigit, $value);
    }

    /**
     * Pause execution for the given number of seconds.
     */
    protected function wait(int $seconds): void
    {
        sleep($seconds);
    }

    protected function api(): Api
    {
        if ($this->api !== null) {
            return $this->api;
        }

        $client = new Client([
            'base_uri' => $this->controlPanelUrl(),
            'verify' => $this->configuration->shouldVerifySsl(),
            'timeout' => 30,
            'connect_timeout' => 10,
            'headers' => [
                'Content-Type' => 'application/json',
            ],
            'handler' => $this->getGuzzleHandlerStack(),
        ]);

        return $this->api = new Api($client, $this->configuration);
    }
}
