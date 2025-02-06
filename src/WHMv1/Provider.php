<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\WHMv1;

use Carbon\Carbon;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Exception\TransferException;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Promise\Utils as PromiseUtils;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Throwable;
use Upmind\ProvisionBase\Provider\Contract\ProviderInterface;
use Upmind\ProvisionProviders\SharedHosting\Category as SharedHosting;
use Upmind\ProvisionBase\Helper;
use Upmind\ProvisionBase\Exception\ProvisionFunctionError;
use Upmind\ProvisionBase\Provider\DataSet\AboutData;
use Upmind\ProvisionProviders\SharedHosting\WHMv1\Api\Request;
use Upmind\ProvisionProviders\SharedHosting\WHMv1\Api\Response;
use Upmind\ProvisionBase\Result\ProviderResult;
use Upmind\ProvisionProviders\SharedHosting\Data\AccountInfo;
use Upmind\ProvisionProviders\SharedHosting\Data\AccountUsage;
use Upmind\ProvisionProviders\SharedHosting\Data\AccountUsername;
use Upmind\ProvisionProviders\SharedHosting\Data\ChangePackageParams;
use Upmind\ProvisionProviders\SharedHosting\Data\ChangePasswordParams;
use Upmind\ProvisionProviders\SharedHosting\Data\CreateParams;
use Upmind\ProvisionProviders\SharedHosting\Data\EmptyResult;
use Upmind\ProvisionProviders\SharedHosting\Data\GetLoginUrlParams;
use Upmind\ProvisionProviders\SharedHosting\Data\GrantResellerParams;
use Upmind\ProvisionProviders\SharedHosting\Data\LoginUrl;
use Upmind\ProvisionProviders\SharedHosting\Data\ResellerOptionParams;
use Upmind\ProvisionProviders\SharedHosting\Data\ResellerPrivileges;
use Upmind\ProvisionProviders\SharedHosting\Data\ResellerUsageData;
use Upmind\ProvisionProviders\SharedHosting\Data\SuspendParams;
use Upmind\ProvisionProviders\SharedHosting\Data\UsageData;
use Upmind\ProvisionProviders\SharedHosting\WHMv1\Data\WHMv1Credentials;
use Upmind\ProvisionProviders\SharedHosting\WHMv1\Softaculous\SoftaculousSdk;

class Provider extends SharedHosting implements ProviderInterface
{
    /**
     * Number of times to attempt to generate a unique username before failing.
     *
     * @var int
     */
    protected const MAX_USERNAME_GENERATION_ATTEMPTS = 5;

    /**
     * @var WHMv1Credentials
     */
    protected $configuration;

    /**
     * @var Client|null
     */
    protected $client;

    /**
     * List of whm functions available to this configuration.
     *
     * @var string[]|null
     */
    protected $functions;

    public function __construct(WHMv1Credentials $configuration)
    {
        $this->configuration = $configuration;
    }

    public static function aboutProvider(): AboutData
    {
        return AboutData::create()
            ->setName('cPanel')
            ->setDescription('Create and manage cPanel accounts and resellers using the WHMv1 API')
            ->setLogoUrl('https://api.upmind.io/images/logos/provision/cpanel-logo@2x.png');
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function testConfiguration(): EmptyResult
    {
        $functionsResult = ProviderResult::createFromProviderOutput($this->listFunctions());

        if ($functionsResult->getStatus() !== ProviderResult::STATUS_OK) {
            $errorMessage = "Configuration is unable to list available API commands: "
                . $functionsResult->getMessage();

            $this->errorResult(
                $errorMessage,
                $functionsResult->getData(),
                $functionsResult->getDebug(),
                $functionsResult->getException()
            );
        }

        $availableFunctions = Arr::get($functionsResult->getData(), 'result_data');

        $requiredFunctions = [
            'createacct',
            'setupreseller',
            'unsetupreseller',
            'accountsummary',
            'changepackage',
            'create_user_session',
            'suspendacct',
            'unsuspendacct',
            'passwd',
            'removeacct'
        ];

        $missingFunctions = collect($requiredFunctions)->diff($availableFunctions);

        if ($missingFunctions->isNotEmpty()) {
            $this->errorResult(
                "Configuration is unable to execute all required API functions",
                ['missing_commands' => $missingFunctions->values()->all()],
                ['available_commands' => $availableFunctions]
            );
        }

        return $this->emptyResult("Credentials verified");
    }

    /**
     * @return string[] Array of API function names
     */
    public function listFunctions()
    {
        if (isset($this->functions)) {
            return $this->functions;
        }

        $response = $this->makeApiCall('GET', 'applist');

        return $this->functions = $this->processResponse($response, function ($responseData) {
            return collect(Arr::get($responseData, 'app'))->sortKeys()->all();
        });
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function create(CreateParams $params): AccountInfo
    {
        if (!$params->domain) {
            $this->errorResult('Domain name is required');
        }

        $username = $params->username ?: $this->generateUsername($params->domain);
        $password = $params->password ?: Helper::generatePassword();
        $domain = strtolower($params->domain ?? '');
        if (Str::startsWith($domain, 'www.')) {
            // remove www. prefix
            $domain = substr($domain, 4);
        }
        $contactemail = $params->email;
        $plan = $this->determinePackageName($params->package_name);
        $customip = $params->custom_ip;
        $reseller = intval($params->as_reseller ?? false);

        if ($params->owns_itself) {
            $owner = $username;
        } else {
            $owner = $params->owner_username ?: $this->configuration->whm_username;
        }

        if ($reseller && !$this->canGrantReseller()) {
            $this->errorResult('Configuration lacks sufficient privileges to create resellers');
        }

        $requestParams = compact(
            'username',
            'password',
            'domain',
            'contactemail',
            'plan',
            'customip',
            'owner',
            'reseller'
        );

        try {
            $response = $this->makeApiCall('POST', 'createacct', $requestParams, ['timeout' => 240]);
            $this->processResponse($response, function ($responseData) {
                return collect($responseData)->filter()->sortKeys()->all();
            });
        } catch (Throwable $createException) {
            if ($this->exceptionWasTimeout($createException)) {
                try {
                    // just in case WHM is running any weird post-create scripts, let's see if we can return success
                    return $this->finishCreate($params, $domain, $username, $password)
                        ->setMessage('Account creation in progress')
                        ->setDebug([
                            'provider_exception' => ProviderResult::formatException(
                                $this->getFirstException($createException)
                            ),
                        ]);
                } catch (Throwable $getInfoException) {
                    if ($createException instanceof ProvisionFunctionError) {
                        throw $createException->withData(array_merge($createException->getData(), [
                            'get_info_error_after_timeout' => $getInfoException->getMessage(),
                            'params' => [
                                'username' => $username,
                                'domain' => $domain,
                                'password' => $password,
                            ],
                        ]));
                    }
                }
            }

            throw $createException;
        }

        return $this->finishCreate($params, $domain, $username, $password);
    }

    /**
     * @throws \GuzzleHttp\Exception\GuzzleException
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    protected function finishCreate(CreateParams $params, string $domain, string $username, string $password): AccountInfo
    {
        try {
            $info = $this->getAccountInfo($username)
                ->setMessage('Account created');

            if ($info->reseller && $params->reseller_options) {
                try {
                    $this->changeResellerOptions($username, $params->reseller_options);
                } catch (\Throwable $e) {
                    // clean-up
                    $this->deleteAccount($username);

                    throw $e;
                }
            }

            if ($this->configuration->softaculous_install) {
                try {
                    $softaculous = $this->getSoftaculous($username, $password);

                    if ($this->configuration->softaculous_install === 'wordpress') {
                        $installation = $softaculous->installWordpress($domain, $params->email);
                    }

                    $info->setSoftware($installation ?? null);
                } catch (\Throwable $e) {
                    // clean-up
                    $this->deleteAccount($username);

                    throw $e;
                }
            }

            return $info;
        } catch (ProvisionFunctionError $e) {
            $errorData = $e->getData();
            $errorData['params'] = [
                'username' => $username,
                'domain' => $domain,
                'password' => $password,
            ];

            throw $e->withData($errorData);
        }
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function grantReseller(GrantResellerParams $params): ResellerPrivileges
    {
        $response = $this->makeApiCall('POST', 'setupreseller', [
            'user' => $params->username,
            'makeowner' => intval($params->owns_itself ?? false),
        ]);
        $this->processResponse($response);

        return ResellerPrivileges::create()
            ->setMessage('Reseller privileges granted')
            ->setReseller(true);
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function revokeReseller(AccountUsername $params): ResellerPrivileges
    {
        $user = $params->username;
        $requestParams = compact('user');

        $response = $this->makeApiCall('POST', 'unsetupreseller', $requestParams);
        $this->processResponse($response);

        return ResellerPrivileges::create()
            ->setMessage('Reseller privileges revoked')
            ->setReseller(false);
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function getInfo(AccountUsername $params): AccountInfo
    {
        return $this->getAccountInfo(
            $params->username,
            isset($params->is_reseller) ? boolval($params->is_reseller) : null
        );
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function getUsage(AccountUsername $params): AccountUsage
    {
        $username = $params->username;

        $promises = [
            'accSummary' => $this->asyncApiCall('POST', 'accountsummary', ['user' => $username]),
            'bandwidth' => $this->asyncApiCall('POST', 'showbw', ['searchtype' => 'user', 'search' => $username]),
            // 'domains' => $this->asyncApiCall('POST', 'get_domain_info', ['user' => $username]),
        ];

        if ($isReseller = ($params->is_reseller ?? $this->userIsReseller($username))) {
            $promises['resellerInfo'] = $this->asyncApiCall('POST', 'resellerstats', ['user' => $username]);
            $promises['resellerSubAccounts'] = $this->asyncApiCall('POST', 'acctcounts', ['user' => $username]);
        }

        $responses = PromiseUtils::all($promises)->wait();

        $accSummary = $this->processResponse($responses['accSummary'], function ($responseData) {
            return collect(Arr::get($responseData, 'acct'))->collapse()->sortKeys()->all();
        });

        $bandwidth = $this->processResponse($responses['bandwidth'], function ($responseData) {
            return Arr::get($responseData, 'acct.0');
        });

        // $domains = $this->processResponse($responses['domains'], function ($responseData) {
        //     return Arr::get($responseData, 'domains');
        // });

        if ($isReseller) {
            $resellerInfo = $this->processResponse($responses['resellerInfo'], function ($responseData) {
                return Arr::get($responseData, 'reseller');
            });

            $resellerSubAccounts = $this->processResponse($responses['resellerSubAccounts'], function ($responseData) {
                return Arr::get($responseData, 'reseller');
            });
        }

        return AccountUsage::create()
            ->setUsageData($this->rawDataToUsageData($accSummary, $bandwidth))
            ->setResellerUsageData(
                $isReseller ? $this->rawDataToResellerUsageData($resellerInfo, $resellerSubAccounts) : null
            );
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function changePackage(ChangePackageParams $params): AccountInfo
    {
        $isReseller = $this->userIsReseller($params->username);

        if ($params->as_reseller) {
            if (!$isReseller) {
                if (!$this->canGrantReseller()) {
                    $this->errorResult('Configuration lacks sufficient privileges to create resellers');
                }

                $this->grantReseller(GrantResellerParams::create($params));
            }

            $this->changeResellerOptions($params->username, $params->reseller_options ?? new ResellerOptionParams());
        } elseif ($isReseller) {
            $this->revokeReseller(AccountUsername::create($params));
        }

        $response = $this->makeApiCall('POST', 'changepackage', [
            'user' => $params->username,
            'pkg' => $this->determinePackageName($params->package_name),
        ]);

        $this->processResponse($response);

        // After updating package, update the primary domain if it was provided.
        if ($params->domain) {
            $modifyAccountResponse = $this->makeApiCall('POST', 'modifyacct', [
                'user' => $params->username,
                'domain' => $params->domain,
            ]);

            $this->processResponse($modifyAccountResponse);
        }

        return $this->getInfo(AccountUsername::create(['username' => $params->username]))
            ->setMessage('Package/limits updated');
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function getLoginUrl(GetLoginUrlParams $params): LoginUrl
    {
        $this->assertNotRoot($params->username);

        $user = $params->username;
        $whm = $params->is_reseller ?? false;
        $service = $whm ? 'whostmgrd' : 'cpaneld';
        $requestParams = compact('user', 'service');

        $response = $this->makeApiCall('POST', 'create_user_session', $requestParams);
        $data = $this->processResponse($response);

        $url = $data['url'];

        if ($this->configuration->sso_destination === 'softaculous_sso' && empty($params->software->install_id)) {
            $this->errorResult('Website software installation ID not given');
        }

        if (in_array($this->configuration->sso_destination, ['softaculous_sso', 'auto'])) {
            if (!empty($params->software->install_id)) {
                $url = Helper::urlAppendQuery($url, [
                    'goto_uri' => SoftaculousSdk::getInstallationLoginUri($params->software->install_id),
                ]);
            }
        }

        return LoginUrl::create()
            ->setMessage('Login URL generated')
            ->setLoginUrl($url)
            ->setForIp(null) //cpanel login urls aren't tied to specific IDs
            ->setExpires(Carbon::createFromTimestampUTC($data['expires']));
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function suspend(SuspendParams $params): AccountInfo
    {
        try {
            $this->suspendAccount($params->username, $params->reason);
        } catch (Throwable $suspendException) {
            if ($this->exceptionWasTimeout($suspendException)) {
                try {
                    // just in case WHM is running any weird post-suspend scripts, let's see if we can return success
                    $info = $this->getInfo(AccountUsername::create(['username' => $params->username]));

                    if ($info->suspended) {
                        // suspend succeeded
                        return $info->setMessage('Account suspension in progress')
                            ->setDebug([
                                'provider_exception' => ProviderResult::formatException(
                                    $this->getFirstException($suspendException)
                                ),
                            ]);
                    }
                } catch (Throwable $getInfoException) {
                    // do nothing...
                }
            }

            throw $suspendException;
        }

        return $this->getInfo(AccountUsername::create(['username' => $params->username]))
            ->setMessage('Account suspended');
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function unSuspend(AccountUsername $params): AccountInfo
    {
        try {
            $this->unSuspendAccount($params->username);
        } catch (Throwable $unsuspendException) {
            if ($this->exceptionWasTimeout($unsuspendException)) {
                try {
                    // just in case WHM is running any weird post-unsuspend scripts, let's see if we can return success
                    $info = $this->getInfo(AccountUsername::create(['username' => $params->username]));

                    if (!$info->suspended) {
                        // unsuspend succeeded
                        return $info->setMessage('Account unsuspension in progress')
                            ->setDebug([
                                'provider_exception' => ProviderResult::formatException(
                                    $this->getFirstException($unsuspendException)
                                ),
                            ]);
                    }
                } catch (Throwable $getInfoException) {
                    // do nothing...
                }
            }

            throw $unsuspendException;
        }

        return $this->getInfo(AccountUsername::create(['username' => $params->username]))
            ->setMessage('Account unsuspended');
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function changePassword(ChangePasswordParams $params): EmptyResult
    {
        $this->assertNotRoot($params->username);

        $user = $params->username;
        $password = $params->password;
        $requestParams = compact('user', 'password');

        $response = $this->makeApiCall('POST', 'passwd', $requestParams);
        $this->processResponse($response);

        return $this->emptyResult('Password changed');
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function terminate(AccountUsername $params): EmptyResult
    {
        $this->deleteAccount($params->username);

        return $this->emptyResult('Account deleted');
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    protected function suspendAccount(string $username, ?string $reason = null): void
    {
        $requestParams = [
            'user' => $username,
            'reason' => $reason,
        ];

        $response = $this->userIsReseller($username)
            ? $this->makeApiCall('POST', 'suspendreseller', $requestParams, ['timeout' => 240])
            : $this->makeApiCall('POST', 'suspendacct', $requestParams);
        $this->processResponse($response);
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    protected function unSuspendAccount(string $username): void
    {
        $requestParams = [
            'user' => $username,
        ];

        $response = $this->userIsReseller($username)
            ? $this->makeApiCall('POST', 'unsuspendreseller', $requestParams, ['timeout' => 240])
            : $this->makeApiCall('POST', 'unsuspendacct', $requestParams);
        $this->processResponse($response);
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    protected function deleteAccount(string $username): void
    {
        $response = $this->userIsReseller($username)
            ? $this->makeApiCall(
                'POST',
                'terminatereseller',
                ['user' => $username, 'terminatereseller' => true],
                ['timeout' => 240]
            )
            : $this->makeApiCall(
                'POST',
                'removeacct',
                ['user' => $username]
            );
        $this->processResponse($response);
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    public function getAccountInfo(string $username, ?bool $isReseller = null): AccountInfo
    {
        $promises = [
            'accSummary' => $this->asyncApiCall('POST', 'accountsummary', ['user' => $username]),
            'nameservers' => $this->asyncApiCall('GET', 'get_nameserver_config'),
        ];

        $responses = PromiseUtils::all($promises)->wait();

        $accSummary = $this->processResponse($responses['accSummary'], function ($responseData) {
            return collect(Arr::get($responseData, 'acct'))->collapse()->sortKeys()->all();
        });

        $nameservers = $this->processResponse($responses['nameservers'], function ($responseData) {
            return Arr::get($responseData, 'nameservers');
        });

        return AccountInfo::create()
            ->setMessage('Account info retrieved')
            ->setUsername($accSummary['user'])
            ->setDomain($accSummary['domain'])
            ->setReseller($isReseller ?? $this->userIsReseller($username))
            ->setServerHostname($this->configuration->hostname)
            ->setPackageName($accSummary['plan'])
            ->setSuspended(boolval($accSummary['suspended']))
            ->setSuspendReason($accSummary['suspendreason'] !== 'not suspended' ? $accSummary['suspendreason'] : null)
            ->setIp($accSummary['ip'])
            ->setNameservers($nameservers);
    }

    /**
     * Determine the package name
     *
     * @throws \Throwable
     */
    protected function determinePackageName(string $packageName): string
    {
        try {
            $this->getPackageInfo($packageName);
            return $packageName;
        } catch (Throwable $e) {
            $usernamePrefix = sprintf('%s_', $this->configuration->whm_username);

            if (!Str::startsWith($packageName, $usernamePrefix)) {
                $packageName = $usernamePrefix . $packageName;

                try {
                    $this->getPackageInfo($packageName);
                    return $packageName;
                } catch (Throwable $e2) {
                    // ignore this exception and re-throw the first
                }
            }

            throw $e;
        }
    }

    /**
     * Get info about a package.
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    protected function getPackageInfo(string $packageName): array
    {
        $response = $this->makeApiCall('GET', 'getpkginfo', [
            'pkg' => $packageName,
        ]);

        return $this->processResponse($response);
    }

    /**
     * Update the given reseller's ACL and/or account/resource limits.
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    protected function changeResellerOptions(string $username, ResellerOptionParams $params): void
    {
        $this->changeResellerACL($username, $params->acl_name);

        $this->changeResellerLimits($username, $params);
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    protected function changeResellerACL(string $username, ?string $aclName): void
    {
        $response = $this->makeApiCall('POST', 'setacls', [
            'reseller' => $username,
            'acllist' => $aclName,
        ]);
        $this->processResponse($response);
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    protected function changeResellerLimits(string $username, ResellerOptionParams $params): void
    {
        $enableResourceLimits = isset($params->bandwidth_mb_limit) || isset($params->diskspace_mb_limit);
        $enableOverselling = $enableResourceLimits && ($params->bandwidth_overselling
            || $params->diskspace_overselling);

        $response = $this->makeApiCall('POST', 'setresellerlimits', [
            'user' => $username,
            'enable_account_limit' => intval(isset($params->account_limit)),
            'account_limit' => $params->account_limit ?? 9999,
            'enable_resource_limits' => intval($enableResourceLimits),
            'diskspace_limit' => $params->diskspace_mb_limit ?? 99999999,
            'bandwidth_limit' => $params->bandwidth_mb_limit ?? 99999999,
            'enable_overselling' => intval($enableOverselling),
            'enable_overselling_diskspace' => intval($params->diskspace_overselling ?? false),
            'enable_overselling_bandwidth' => intval($params->bandwidth_overselling ?? false),
        ]);
        $this->processResponse($response);
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    protected function userIsReseller(string $username): ?bool
    {
        if ($this->canGrantReseller()) {
            $response = $this->makeApiCall('POST', 'listresellers');
            $data = $this->processResponse($response);

            return in_array($username, $data['reseller']);
        }

        return null; // probably not, but can't say for sure
    }

    protected function canGrantReseller(): bool
    {
        return in_array('listresellers', $this->listFunctions());
    }

    /**
     * @param string $base Base string to generate a username from
     * @param int $count Number of attempts so far
     *
     * @return string A unique valid username
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    protected function generateUsername(string $base, int $count = 0): string
    {
        if ($count >= self::MAX_USERNAME_GENERATION_ATTEMPTS) {
            $this->errorResult('Unable to generate a unique username');
        }

        // usernames must be of a certain length, start with a letter and only contain alpha-numeric chars
        $username = substr(
            preg_replace('/^[^a-z]+/', '', preg_replace('/[^a-z0-9]/', '', strtolower($base))),
            0,
            $this->getMaxUsernameLength()
        );

        if ($this->newUsernameIsValid($username)) {
            return $username;
        }

        $username = substr($username, 0, $this->getMaxUsernameLength() - 1) . rand(1, 9);

        return $this->generateUsername($username, $count + 1);
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    protected function newUsernameIsValid(string $username): bool
    {
        $response = $this->makeApiCall('POST', 'verify_new_username', [
            'user' => $username,
        ]);

        try {
            $this->processResponse($response);
            return true;
        } catch (ProvisionFunctionError $e) {
            if (Str::contains($e->getMessage(), 'already has')) {
                // a message like 'This system already has an account named "$username"'
                return false;
            }

            throw $e;
        }
    }

    protected function getMaxUsernameLength(): int
    {
        return 8; //some server versions support 16, but earlier only support max 8
    }

    /**
     * @param array $accSummaryData Raw data from `accountsummary`
     * @param array $bandwidthData Raw data from `showbw`
     */
    protected function rawDataToUsageData(array $accSummaryData, array $bandwidthData): UsageData
    {
        $diskUsedMb = round(rtrim($accSummaryData['diskused'] ?: '', 'M') ?: 0);
        $diskLimitMb = $accSummaryData['disklimit'] !== 'unlimited' ? rtrim($accSummaryData['disklimit'], 'M') : null;
        $diskPcUsed = is_numeric($diskLimitMb)
            ? round(($diskUsedMb) / $diskLimitMb * 100, 2) . '%'
            : null;

        $bandwidthUsedMb = round($bandwidthData['totalbytes'] / 1024 / 1024);
        $bandwidthLimitMb = $bandwidthData['bwlimited'] ? round($bandwidthData['limit'] / 1024 / 1024) : null;
        $bandwidthPcUsed = is_numeric($bandwidthLimitMb)
            ? round(($bandwidthUsedMb ?: 0) / $bandwidthLimitMb * 100, 2) . '%'
            : null;

        $inodesUsed = $accSummaryData['inodesused'] ?? 0;
        $inodesLimit = $accSummaryData['inodeslimit'] !== 'unlimited' ? $accSummaryData['inodeslimit'] : null;
        $inodesPcUsed = is_numeric($inodesLimit)
            ? round(($inodesUsed ?: 0) / $inodesLimit * 100, 2) . '%'
            : null;

        return new UsageData([
            'disk_mb' => [
                'used' => $diskUsedMb,
                'limit' => $diskLimitMb,
                'used_pc' => $diskPcUsed,
            ],
            'bandwidth_mb' => [
                'used' => $bandwidthUsedMb,
                'limit' => $bandwidthLimitMb,
                'used_pc' => $bandwidthPcUsed,
            ],
            'inodes' => [
                'used' => $inodesUsed,
                'limit' => $inodesLimit,
                'used_pc' => $inodesPcUsed,
            ],
        ]);
    }

    /**
     * @param array $resellerStatsData Raw data from `resellerstats`
     * @param array $accountCountData Raw data from `acctcounts`
     */
    protected function rawDataToResellerUsageData(array $resellerStatsData, array $accountCountData): ResellerUsageData
    {
        $diskUsedMb = round($resellerStatsData['diskused'] ?: 0);
        $diskLimitMb = $resellerStatsData['diskquota'] ?: null;
        $diskPcUsed = is_numeric($diskLimitMb)
            ? round(($diskUsedMb) / $diskLimitMb * 100, 2) . '%'
            : null;

        $bandwidthUsedMb = round($resellerStatsData['totalbwused'] ?: 0);
        $bandwidthLimitMb = $resellerStatsData['bandwidthlimit'] ?: null;
        $bandwidthPcUsed = is_numeric($bandwidthLimitMb)
            ? round(($bandwidthUsedMb ?: 0) / $bandwidthLimitMb * 100, 2) . '%'
            : null;

        $subAccountsUsed = ($accountCountData['active'] ?: 0) + ($accountCountData['suspended'] ?: 0);
        $subAccountsLimit = $accountCountData['limit'] ?: null;
        $subAccountsPcUsed = is_numeric($subAccountsLimit)
            ? round(($subAccountsUsed ?: 0) / $subAccountsLimit * 100, 2) . '%'
            : null;

        return new ResellerUsageData([
            'disk_mb' => [
                'used' => $diskUsedMb,
                'limit' => $diskLimitMb,
                'used_pc' => $diskPcUsed,
            ],
            'bandwidth_mb' => [
                'used' => $bandwidthUsedMb,
                'limit' => $bandwidthLimitMb,
                'used_pc' => $bandwidthPcUsed,
            ],
            'sub_accounts' => [
                'used' => $subAccountsUsed,
                'limit' => $subAccountsLimit,
                'used_pc' => $subAccountsPcUsed,
            ],
        ]);
    }

    protected function countAddonDomains(array $domains, string $username): int
    {
        $count = 0;

        foreach ($domains as $domain) {
            if ($domain['user'] === $username && $domain['domain_type'] === 'addon') {
                $count++;
            }
        }

        return $count;
    }

    /**
     * Determine whether any error in the chain of the given exception was a
     * request timeout.
     */
    protected function exceptionWasTimeout(Throwable $e): bool
    {
        if ($e instanceof ConnectException && Str::contains($e->getMessage(), 'Operation timed out')) {
            return true;
        }

        if ($e instanceof RequestException && $e->hasResponse()) {
            $httpCode = $e->getResponse()->getStatusCode();

            if ($httpCode === 524) {
                /** @link https://en.wikipedia.org/wiki/List_of_HTTP_status_codes#524 */
                return true;
            }
        }

        if ($previous = $e->getPrevious()) {
            return $this->exceptionWasTimeout($previous);
        }

        return false;
    }

    /**
     * Returns the first exception thrown in the given error chain.
     */
    protected function getFirstException(Throwable $e): Throwable
    {
        while ($previous = $e->getPrevious()) {
            $e = $previous;
        }

        return $e;
    }

    /**
     * @param string $method HTTP method
     * @param string $function WHMv1 API function name
     * @param array $params API function params
     * @param array $requestOptions Guzzle request options
     *
     * @return \Upmind\ProvisionProviders\SharedHosting\WHMv1\Api\Response
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    protected function makeApiCall(
        string $method,
        string $function,
        array $params = [],
        array $requestOptions = []
    ): Response {
        return $this->asyncApiCall($method, $function, $params, $requestOptions)->wait();
    }

    /**
     * @param string $method HTTP method
     * @param string $function WHMv1 API function name
     * @param array $params API function params
     * @param array $requestOptions Guzzle request options
     *
     * @return PromiseInterface
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     * @throws \Throwable
     */
    protected function asyncApiCall(
        string $method,
        string $function,
        array $params = [],
        array $requestOptions = []
    ): PromiseInterface {
        $client = $this->getClient();
        $request = new Request($client, $method, $function, $params, $requestOptions);

        return $request->getPromise()->otherwise(function ($e) use ($function) {
            $data = [
                'function' => $function,
            ];

            if ($e instanceof TransferException) {
                if ($e instanceof RequestException && $e->hasResponse()) {
                    /** @var \Psr\Http\Message\ResponseInterface $response */
                    $response = $e->getResponse();
                    $responseBody = $response->getBody()->__toString();
                    $resultData = json_decode($responseBody, true);

                    $message = sprintf('WHM API Request Error: %s', $response->getReasonPhrase() ?: 'Unknown Error');

                    $data['http_code'] = $response->getStatusCode();
                    $data['result_data'] = $resultData;

                    if (!$resultData) {
                        $data['response_body'] = Str::limit($responseBody, 500);
                    }
                } else {
                    $message = 'WHM API Connection Error';
                    $data['error'] = $e->getMessage();
                }

                if ($this->exceptionWasTimeout($e)) {
                    $message = 'WHM API Request Timeout';
                }

                $this->errorResult($message, $data, [], $e);
            }

            throw $e;
        });
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    protected function processResponse(
        Response $response,
        ?callable $successDataTransformer = null
    ): array {
        $http_code = $response->getHttpCode();
        $message = $response->getMessage();
        $result_data = $response->getBodyAssoc('data', []);
        $result_meta = $response->getBodyAssoc('metadata');

        if ($response->isSuccess()) {
            if ($successDataTransformer) {
                $result_data = transform($result_data, $successDataTransformer);
            }

            return $result_data;
        }

        $data = ['http_code' => $http_code, 'result_data' => $result_data, 'result_meta' => $result_meta];

        if (empty($result_data)) {
            $data['response_body'] = Str::limit($response->getPsr7()->getBody()->__toString(), 300);
        }

        $this->errorResult('WHM API Error: ' . $message, $data);
    }

    protected function getSoftaculous(string $username, string $password): SoftaculousSdk
    {
        return new SoftaculousSdk($username, $password, $this->configuration, new Client([
            'handler' => $this->getGuzzleHandlerStack(),
        ]));
    }

    /**
     * @param string $username
     */
    protected function assertNotRoot($username)
    {
        if (0 === strcasecmp(trim((string)$username), 'root')) {
            $this->errorResult('Cannot perform this action on root');
        }
    }

    protected function getClient(): Client
    {
        if ($this->client) {
            return $this->client;
        }

        return $this->client = new Client([
            'base_uri' => sprintf('https://%s:2087/json-api/', $this->configuration->hostname),
            'headers' => [
                'Accept' => 'application/json',
                'Authorization' => sprintf(
                    'whm %s:%s',
                    $this->configuration->whm_username,
                    $this->configuration->api_key
                ),
            ],
            'query' => [
                'api.version' => 1
            ],
            'connect_timeout' => 10,
            'timeout' => 60,
            'http_errors' => true,
            'allow_redirects' => false,
            'handler' => $this->getGuzzleHandlerStack(),
        ]);
    }
}
