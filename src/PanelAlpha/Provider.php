<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\PanelAlpha;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use Throwable;
use Carbon\Carbon;
use Upmind\ProvisionBase\Exception\ProvisionFunctionError;
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
use Upmind\ProvisionProviders\SharedHosting\PanelAlpha\Data\Configuration;

class Provider extends Category implements ProviderInterface
{
    protected const MAX_USERNAME_LENGTH = 10;

    protected Configuration $configuration;
    protected ?Api $api = null;

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
            ->setName('PanelAlpha')
            ->setDescription('Create and manage PanelAlpha accounts and resellers using the PanelAlpha API')
            ->setLogoUrl('https://api.upmind.io/images/logos/provision/panel-alpha-logo.png');
    }

    /**
     * @inheritDoc
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function create(CreateParams $params): AccountInfo
    {
        if (mb_strlen($params->email) > 255) {
            $this->errorResult('Email address is too long');
        }

        if ($params->password !== null && mb_strlen($params->password) < 8) {
            $this->errorResult('Password must be at least 8 characters long');
        }

        // Generate a random username from the domain, if username is not provided.
        $name = $params->username ?? $this->generateName((string) $params->domain);

        if (empty(trim($name))) {
            $name = $params->email;
        }

        try {
            $message = 'Account created without hosting instance as no domain was provided';

            $userId = $this->findOrCreateUser($params, $name);

            $serviceId = $this->api()->createService($params, $userId);

            // Create instance if domain is provided.
            if ($params->domain) {
                $this->api()->createInstance($userId, $serviceId, $params->domain, $name);

                $message = 'Account created with hosting instance for: ' . $params->domain;
            }

            return $this->_getInfo($userId, $params->domain, $message);
        } catch (Throwable $e) {
            $this->handleException($e);
        }
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    protected function _getInfo(string $userId, ?string $domain, string $message): AccountInfo
    {
        $info = $this->api()->getAccountData($userId, $domain);

        return AccountInfo::create($info)->setMessage($message);
    }

    /**
     * @inheritDoc
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function getInfo(AccountUsername $params): AccountInfo
    {
        try {
            // Use customer_id if available, otherwise use username which should be an email address.
            return $this->_getInfo(
                is_int($params->customer_id) || is_string($params->customer_id)
                    ? (string) $params->customer_id
                    : $params->username,
                $params->domain,
                'Account info retrieved',
            );
        } catch (Throwable $e) {
            $this->handleException($e);
        }
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function getUsage(AccountUsername $params): AccountUsage
    {
        try {
            // Use customer_id if available, otherwise use username which should be an email address.
            $usage = $this->api()->getAccountUsage(
                is_int($params->customer_id) || is_string($params->customer_id)
                    ? (string) $params->customer_id
                    : $params->username,
                $params->domain
            );

            return AccountUsage::create()
                ->setUsageData($usage);
        } catch (Throwable $e) {
            $this->handleException($e);
        }
    }

    /**
     * @inheritDoc
     *
     * Username param should be either the User ID, or the User email address.
     * User's username is not unique, so we cannot use it to identify the user.
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function getLoginUrl(GetLoginUrlParams $params): LoginUrl
    {
        try {
            // Use customer_id if available, otherwise use username which should be an email address.
            $loginUrl = $this->api()->getLoginUrl(is_int($params->customer_id) || is_string($params->customer_id)
                ? (string) $params->customer_id
                : $params->username
            );

            return LoginUrl::create()
                ->setLoginUrl($loginUrl)
                ->setExpires(Carbon::now()->addMinutes(30));
        } catch (Throwable $e) {
            $this->handleException($e);
        }
    }

    /**
     * @inheritDoc
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function changePassword(ChangePasswordParams $params): EmptyResult
    {
        try {
            // Use customer_id if available, otherwise use username (should be email)
            $this->api()->updatePassword(
                is_int($params->customer_id) || is_string($params->customer_id)
                    ? (string) $params->customer_id
                    : $params->username,
                $params->password
            );

            return $this->emptyResult('Password changed');
        } catch (Throwable $e) {
            $this->handleException($e);
        }
    }

    /**
     * @inheritDoc
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function changePackage(ChangePackageParams $params): AccountInfo
    {
        try {
            if (!$params->domain) {
                $this->errorResult('Domain is required');
            }

            // Use customer_id if available, otherwise use username (should be email)
            $userId = is_int($params->customer_id) || is_string($params->customer_id)
                ? (string) $params->customer_id
                : $params->username;

            $this->api()->updatePackage($userId, $params->package_name, $params->domain);

            return $this->_getInfo($userId, $params->domain, 'Package changed');
        } catch (Throwable $e) {
            $this->handleException($e);
        }
    }

    /**
     * @inheritDoc
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function suspend(SuspendParams $params): AccountInfo
    {
        try {
            // Use customer_id if available, otherwise use username
            $userId = is_int($params->customer_id) || is_string($params->customer_id)
                ? (string) $params->customer_id
                : $params->username;

            $this->api()->suspendAccount($userId);

            return $this->_getInfo($userId, $params->domain, 'Account suspended');
        } catch (Throwable $e) {
            $this->handleException($e);
        }
    }

    /**
     * @inheritDoc
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function unSuspend(AccountUsername $params): AccountInfo
    {
        try {
            // Use customer_id if available, otherwise use username
            $userId = is_int($params->customer_id) || is_string($params->customer_id)
                ? (string) $params->customer_id
                : $params->username;

            $this->api()->unsuspendAccount($userId);

            return $this->_getInfo($userId, $params->domain, 'Account unsuspended');
        } catch (Throwable $e) {
            $this->handleException($e);
        }
    }

    /**
     * @inheritDoc
     *
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function terminate(AccountUsername $params): EmptyResult
    {
        try {
            // Use customer_id if available, otherwise use username
            $this->api()->deleteAccount(is_int($params->customer_id) || is_string($params->customer_id)
                ? (string) $params->customer_id
                : $params->username
            );

            return $this->emptyResult('Account deleted');
        } catch (Throwable $e) {
            $this->handleException($e);
        }
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
     * @return no-return
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    protected function handleException(Throwable $e): void
    {
        if (($e instanceof RequestException) && $e->hasResponse()) {
            /** @var \Psr\Http\Message\ResponseInterface $response */
            $response = $e->getResponse();

            $body = trim($response->getBody()->__toString());
            $responseData = json_decode($body, true);

            $errorMessage = $responseData['message'] ?? 'unknown error';

            $this->errorResult(
                sprintf('Provider API Error: %s', $errorMessage),
                ['response_data' => $responseData],
                [],
                $e
            );
        }

        // Throw the exception if it's not a RequestException
        throw $e;
    }

    protected function api(): Api
    {
        if ($this->api) {
            return $this->api;
        }

        $client = new Client([
            'base_uri' => sprintf('https://%s:%s', $this->configuration->hostname, $this->configuration->port),
            'headers' => [
                'Authorization' => 'Bearer ' . $this->configuration->api_token,
                'Accept' => 'application/json',
                'Content-Type' => 'application/json',
            ],
            'verify' => false,
            'connect_timeout' => 10,
            'timeout' => 60,
            'http_errors' => true,
            'allow_redirects' => false,
            'handler' => $this->getGuzzleHandlerStack(),
        ]);

        return $this->api = new Api($client, $this->configuration);
    }

    /**
     * Find an existing stack user by email (if auto-detect enabled), or create
     * a new one.
     *
     * @return string User ID.
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    private function findOrCreateUser(CreateParams $params, string $name): string
    {
        if ($params->customer_id !== null) {
            return (string) $params->customer_id;
        }

        // re-use customer email address for stack user
        try {
            return $this->api()->findUserIdByEmail($params->email);
        } catch (ProvisionFunctionError $e) {
            // Create user if not found
        }

        return (string) $this->api()->createUser($params, $name)['id'];
    }

    private function generateName(string $base): string
    {
        return substr(
            preg_replace('/^[^a-z]+/', '', preg_replace('/[^a-z0-9]/', '', strtolower($base))),
            0,
            self::MAX_USERNAME_LENGTH
        );
    }
}
