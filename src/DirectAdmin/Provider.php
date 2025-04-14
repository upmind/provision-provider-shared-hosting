<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\DirectAdmin;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ServerException;
use Throwable;
use Carbon\Carbon;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\TransferException;
use Illuminate\Support\Str;
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
use Upmind\ProvisionProviders\SharedHosting\DirectAdmin\Data\Configuration;

class Provider extends Category implements ProviderInterface
{
    /**
     * @var Configuration
     */
    protected Configuration $configuration;
    protected const MAX_USERNAME_LENGTH = 10;
    protected const STATUS_AUTO = 'auto';
    protected const STATUS_SERVER = 'server';
    protected const STATUS_LIST = ['server', 'shared', 'free'];

    /**
     * @var Api|null
     */
    protected $api;

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
            ->setName('DirectAdmin')
            ->setDescription('Create and manage DirectAdmin accounts and resellers using the DirectAdmin API')
            ->setLogoUrl('https://api.upmind.io/images/logos/provision/direct-admin-logo.png');
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
        $asReseller = boolval($params->as_reseller ?? false);

        if (!$asReseller && !$params->domain) {
            $this->errorResult('Domain name is required');
        }

        if (empty($params->custom_ip)) {
            // Check that the ip status is set, if not set Server as default.
            $status = !empty($this->configuration->ip_status) ? $this->configuration->ip_status : self::STATUS_SERVER;
            $customIp = $status !== self::STATUS_AUTO ? $this->freeIpByPriority($status) :
                $this->freeIpByPriority('');
        } else {
            $customIp = $params->custom_ip;
        }

        $username = $params->username ?: $this->generateUsername($params->domain);

        try {
            $this->api()->createAccount(
                $params,
                $username,
                $asReseller,
                $customIp
            );

            if ($asReseller) {
                return $this->_getInfo($username, 'Reseller account created');
            }

            return $this->_getInfo($username, 'Account created');
        } catch (Throwable $e) {
            $this->handleException($e);
        }
    }

    protected function generateUsername(string $base): string
    {
        return substr(
            preg_replace('/^[^a-z]+/', '', preg_replace('/[^a-z0-9]/', '', strtolower($base))),
            0,
            self::MAX_USERNAME_LENGTH
        );
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
     * @throws \Throwable
     */
    public function getInfo(AccountUsername $params): AccountInfo
    {
        try {
            return $this->_getInfo(
                $params->username,
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
            $usage = $this->api()->getAccountUsage($params->username);

            return AccountUsage::create()
                ->setUsageData($usage);
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
    public function getLoginUrl(GetLoginUrlParams $params): LoginUrl
    {
        $this->assertNotRoot($params->username);

        try {
            $loginUrl = $this->api()->getLoginUrl($params->username, $params->user_ip);

            return LoginUrl::create()
                ->setLoginUrl($loginUrl)
                // ->setForIp($params->user_ip)
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
        $this->assertNotRoot($params->username);

        try {
            $this->api()->updatePassword($params->username, $params->password);

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
            $this->api()->updatePackage($params->username, $params->package_name);

            return $this->_getInfo(
                $params->username,
                'Package changed'
            );
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
            $this->api()->suspendAccount($params->username);

            return $this->_getInfo($params->username, 'Account suspended');
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
            $this->api()->unsuspendAccount($params->username);

            return $this->_getInfo($params->username, 'Account unsuspended');
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
            $this->api()->deleteAccount($params->username);

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
     * @param string $username
     */
    protected function assertNotRoot($username)
    {
        if (0 === strcasecmp(trim((string)$username), $this->configuration->username)) {
            $this->errorResult('Cannot perform this action on configuration user itself');
        }

        if (0 === strcasecmp(trim((string)$username), 'root')) {
            $this->errorResult('Cannot perform this action on root');
        }
    }

    /**
     * @return no-return
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    protected function handleException(Throwable $e): void
    {
        if ($e instanceof TransferException) {
            if (($e instanceof ServerException) && $e->hasResponse()) {
                $response = $e->getResponse();
                $reason = $response->getReasonPhrase();
                $responseBody = $response->getBody()->__toString();
                $responseData = json_decode($responseBody, true);

                $errorMessage = null;

                // If we have an error key in the response data, use it as the error message.
                if (isset($responseData['error'])) {
                    $errorMessage = $responseData['error'] . '. ' . ($responseData['result'] ?? 'N/A Response Result');
                }

                // If still null, set the reason from response reason phrase.
                if ($errorMessage === null) {
                    $errorMessage = $reason;
                }

                $this->errorResult(
                    sprintf('Provider API error: %s', empty($errorMessage) ? null : $errorMessage),
                    [],
                    ['response_data' => $responseData ?? null],
                    $e
                );
            }

            if (Str::contains($e->getMessage(), 'cURL error')) {
                $this->errorResult('Provider API connection error', [
                    'exception' => get_class($e),
                    'message' => $e->getMessage(),
                ]);
            }
        }

        // let the provision system handle this one
        throw $e;
    }

    protected function api(): Api
    {
        if ($this->api) {
            return $this->api;
        }

        $credentials = base64_encode("{$this->configuration->username}:{$this->configuration->password}");

        $client = new Client([
            'base_uri' => sprintf('https://%s:%s', $this->configuration->hostname, $this->configuration->port ?? 2222),
            'headers' => [
                'Authorization' => ['Basic ' . $credentials],
            ],
            'connect_timeout' => 10,
            'timeout' => 60,
            'http_errors' => true,
            'allow_redirects' => false,
            'handler' => $this->getGuzzleHandlerStack(),
        ]);

        return $this->api = new Api($client, $this->configuration);
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    protected function freeIpByPriority(string $ipStatus): string
    {
        if (empty($ipStatus)) {
            foreach(self::STATUS_LIST as $item) {
                $ip = $this->api()->freeIpList($item);
                if (!empty($ip)) {
                    return $ip;
                }
            }
        }

        $ip = $this->api()->freeIpList($ipStatus);

        if (!empty($ip)) {
            return $ip;
        }

        $this->errorResult('Domain IP is required, no free ips found');
    }
}
