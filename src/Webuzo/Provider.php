<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\Webuzo;

use GuzzleHttp\Client;
use Illuminate\Support\Str;
use Throwable;
use Upmind\ProvisionBase\Provider\Contract\ProviderInterface;
use Upmind\ProvisionBase\Provider\DataSet\AboutData;
use Upmind\ProvisionProviders\SharedHosting\Category;
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
use Upmind\ProvisionProviders\SharedHosting\Webuzo\Data\Configuration;

/**
 * Webuzo provision provider.
 */
class Provider extends Category implements ProviderInterface
{
    protected const MAX_USERNAME_LENGTH = 10;

    protected Configuration $configuration;
    protected ?Api $api = null;
    private bool $endUserApi = false;

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
            ->setName('Webuzo')
            ->setDescription('Create and manage Webuzo accounts and resellers using the Webuzo API')
            ->setLogoUrl('https://api.upmind.io/images/logos/provision/webuzo-logo.png');
    }

    /**
     * @inheritDoc
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function create(CreateParams $params): AccountInfo
    {
        if (!$params->domain) {
            $this->errorResult('Domain name is required');
        }

        $asReseller = boolval($params->as_reseller ?? false);

        $username = $params->username ?: $this->generateUsername($params->domain);

        $this->api()->createAccount(
            $params,
            $username,
            $asReseller
        );

        return $this->_getInfo($username, 'Account created');
    }

    protected function generateUsername(string $base): string
    {
        // Lowercase
        $username = mb_strtolower($base);

        // Remove all non-alphanumeric characters
        $username = preg_replace('/[^a-z0-9]/', '', $username);

        // Remove leading non-alphabetic characters
        $username = preg_replace('/^[^a-z]+/', '', $username);

        // Limit to MAX_USERNAME_LENGTH characters
        return substr($username, 0, self::MAX_USERNAME_LENGTH);
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    protected function _getInfo(string $username, string $message): AccountInfo
    {
        $info = $this->api()->getAccountData($username);

        return AccountInfo::create($info)->setMessage($message);
    }

    /**
     * @inheritDoc
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function getInfo(AccountUsername $params): AccountInfo
    {
        return $this->_getInfo(
            $params->username,
            'Account info retrieved',
        );
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function getUsage(AccountUsername $params): AccountUsage
    {
        $usage = $this->api()->getAccountUsage($params->username);

        return AccountUsage::create()
            ->setUsageData($usage);
    }

    /**
     * @inheritDoc
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function getLoginUrl(GetLoginUrlParams $params): LoginUrl
    {
        $loginUrl = $this->api(true)->getLoginUrl($params->username);

        if (Str::contains($loginUrl, 'webuzo.whgi.net')) {
            $loginUrl = str_replace('webuzo.whgi.net', $this->configuration->hostname, $loginUrl);
        }

        return LoginUrl::create()
            ->setLoginUrl($loginUrl);
    }

    /**
     * @inheritDoc
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function changePassword(ChangePasswordParams $params): EmptyResult
    {
        $this->api()->updatePassword($params->username, $params->password);

        return $this->emptyResult('Password changed');
    }

    /**
     * @inheritDoc
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function changePackage(ChangePackageParams $params): AccountInfo
    {
        $this->api()->updatePackage($params->username, $params->package_name);

        return $this->_getInfo(
            $params->username,
            'Package changed'
        );
    }

    /**
     * @inheritDoc
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function suspend(SuspendParams $params): AccountInfo
    {
        $this->api()->suspendAccount($params->username);

        return $this->_getInfo($params->username, 'Account suspended');
    }

    /**
     * @inheritDoc
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function unSuspend(AccountUsername $params): AccountInfo
    {
        $this->api()->unsuspendAccount($params->username);

        return $this->_getInfo($params->username, 'Account unsuspended');
    }

    /**
     * @inheritDoc
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function terminate(AccountUsername $params): EmptyResult
    {
        $this->api()->deleteAccount($params->username);

        return $this->emptyResult('Account deleted');
    }

    /**
     * @inheritDoc
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function grantReseller(GrantResellerParams $params): ResellerPrivileges
    {
        $this->api()->setReseller($params->username, 1);

        return ResellerPrivileges::create()
            ->setMessage('Reseller privileges granted')
            ->setReseller(true);
    }

    /**
     * @inheritDoc
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function revokeReseller(AccountUsername $params): ResellerPrivileges
    {
        $this->api()->setReseller($params->username, 0);

        return ResellerPrivileges::create()
            ->setMessage('Reseller privileges revoked')
            ->setReseller(false);
    }

    /**
     * @return no-return
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    protected function handleException(Throwable $e): void
    {
        // let the provision system handle this one
        throw $e;
    }

    protected function api(bool $endUser = false): Api
    {
        // If the API is already set, and the endUser setting matches, return it.
        if ($this->endUserApi === $endUser && $this->api) {
            return $this->api;
        }

        // Otherwise, recreate the API instance.
        $auth = '';

        // If authentication is set to Login credentials for Basic Auth, use the Username & Password.
        if ($this->configuration->authenticateWithBasicAuth()) {
            $auth = $this->configuration->username . ':' . ((string) $this->configuration->password) . '@';
        }

        $client = new Client([
            'base_uri' => sprintf(
                'https://%s%s:%s',
                $auth,
                $this->configuration->hostname,
                $endUser ? 2003 : 2005 // Different ports for end-user and admin API
            ),
            'headers' => [
                'Accept' => 'application/json',
            ],
            'connect_timeout' => 10,
            'timeout' => 60,
            'verify' => false,
            'http_errors' => true,
            'allow_redirects' => false,
            'handler' => $this->getGuzzleHandlerStack(),
        ]);

        return $this->api = new Api($client, $this->configuration);
    }
}
