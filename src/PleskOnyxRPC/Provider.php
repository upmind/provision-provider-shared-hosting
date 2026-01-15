<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\PleskOnyxRPC;

use Carbon\Carbon;
use Illuminate\Support\Str;
use Upmind\ProvisionBase\Provider\Contract\ProviderInterface;
use Upmind\ProvisionProviders\SharedHosting\Category as SharedHosting;
use Upmind\ProvisionBase\Result\ProviderResult;
use Upmind\ProvisionBase\Helper;
use Upmind\ProvisionProviders\SharedHosting\PleskOnyxRPC\Api\Client;
use PleskX\Api\Exception as PleskException;
use PleskX\Api\Client\Exception as PleskClientException;
use PleskX\Api\XmlResponse;
use Upmind\ProvisionProviders\SharedHosting\PleskOnyxRPC\Errors\ServiceMisconfiguration;
use Upmind\ProvisionBase\Provider\Helper\Exception\Contract\ProviderError;
use Throwable;
use Upmind\ProvisionBase\Exception\ProvisionFunctionError;
use Upmind\ProvisionBase\Provider\DataSet\AboutData;
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
use Upmind\ProvisionProviders\SharedHosting\Data\ResellerPrivileges;
use Upmind\ProvisionProviders\SharedHosting\Data\SuspendParams;
use Upmind\ProvisionProviders\SharedHosting\PleskOnyxRPC\Data\PleskOnyxCredentials;

class Provider extends SharedHosting implements ProviderInterface
{
    /**
     * Number of times to attempt to generate a unique username before failing.
     *
     * @var int
     */
    protected const MAX_USERNAME_GENERATION_ATTEMPTS = 5;

    /**
     * @var PleskOnyxCredentials
     */
    protected $configuration;

    /**
     * @var Client
     */
    protected $client;

    public function __construct(PleskOnyxCredentials $configuration)
    {
        $this->configuration = $configuration;
    }

    public static function aboutProvider(): AboutData
    {
        return AboutData::create([
            'name' => 'Plesk',
            'description' => 'Create and manage Plesk accounts and resellers using the Onyx RPC API',
            'logo_url' => 'https://api.upmind.io/images/logos/provision/plesk-logo@2x.png',
        ]);
    }

    public function testConfiguration()
    {
        try {
            $client = $this->getClient();

            $admin = $client->server()->getAdmin(); //administrator-only api function

            return $this->okResult('Credentials verified');
        } catch (PleskException | PleskClientException | ProviderError $e) {
            return $this->handleException($e, 'Configuration test');
        }
    }

    public function create(CreateParams $params): AccountInfo
    {
        if (!$params->domain) {
            throw $this->errorResult('Domain name is required');
        }

        if ($params->as_reseller) {
            return $this->createReseller($params);
        }

        $login = $params->username ?? $this->generateUsername($params->domain);
        $ownerLogin = $params->owner_username;
        $email = $params->email;
        $passwd = $params->password ?: Helper::generatePassword();
        $pname = $params->customer_name ?? $login;
        $domain = $params->domain;
        $ip_address = $params->custom_ip;

        $client = $this->getClient();

        if ($params->customer_id) {
            $customerId = $params->customer_id;
        } else {
            try {
                //create customer
                $customerParams = [
                    'pname' => $pname,
                    'login' => $login,
                    'passwd' => $passwd,
                    'email' => $email,
                ];

                if ($ownerLogin) {
                    $customerParams['owner-login'] = $ownerLogin;
                }

                $newCustomer = $client->customer()->create($customerParams);
                $customerId = $newCustomer->id;
            } catch (PleskException | PleskClientException | ProviderError $e) {
                return $this->handleException($e, 'Create customer');
            }
        }

        if (!$ip_address) {
            try {
                //get a shared ip to use
                foreach ($client->ip()->get() as $ipInfo) {
                    if ($ipInfo->type === 'shared') {
                        $ip_address = $ipInfo->ipAddress;
                        break;
                    }
                }

                if (!$ip_address) {
                    throw ServiceMisconfiguration::forNoSharedIps();
                }
            } catch (PleskException | PleskClientException | ProviderError $e) {
                //cleanup customer
                if (isset($newCustomer)) {
                    $client->customer()->delete('id', $newCustomer->id);
                }

                return $this->handleException($e, 'Get IPs');
            } catch (Throwable $e) {
                //cleanup customer
                if (isset($newCustomer)) {
                    $client->customer()->delete('id', $newCustomer->id);
                }
                //let ProviderJob object handle this one
                throw $e;
            }
        }

        try {
            $plan = $this->getPlan($params->package_name);
        } catch (PleskException | PleskClientException | ProviderError $e) {
            //cleanup customer
            if (isset($newCustomer)) {
                $client->customer()->delete('id', $newCustomer->id);
            }

            return $this->handleException($e, 'Get plan info');
        }

        try {
            //create webspace
            $webspaceParams = [
                'name' => $domain,
                'owner-id' => $customerId,
                'ip_address' => $ip_address,
                'htype' => 'vrt_hst'
            ];
            $hostingParams = [
                'ftp_login' => $login,
                'ftp_password' => $passwd
            ];
            $webspace = $client->webspace()->create($webspaceParams, $hostingParams, $plan->name);
        } catch (PleskException | PleskClientException | ProviderError $e) {
            //cleanup customer
            if (isset($newCustomer)) {
                $client->customer()->delete('id', $newCustomer->id);
            }

            return $this->handleException($e, 'Create webspace');
        } catch (Throwable $e) {
            //cleanup customer
            if (isset($newCustomer)) {
                $client->customer()->delete('id', $newCustomer->id);
            }
            //let ProviderJob object handle this one
            throw $e;
        }

        return $this->getInfo(new AccountUsername(['username' => $login]))
            ->setMessage('Subscription created')
            ->setDebug(['customer' => $newCustomer ?? $customerId, 'webspace' => $webspace]);
    }

    protected function createReseller(CreateParams $params): AccountInfo
    {
        $login = $params->username ?? $this->generateUsername($params->domain);
        $ownerLogin = $params->owner_username;
        $email = $params->email;
        $passwd = $params->password;
        $pname = $params->customer_name ?? $login;
        $domain = $params->domain;
        $plan = $params->package_name;
        $ip_address = $params->custom_ip;

        if ($ownerLogin) {
            return $this->errorResult("Cannot specify owner_username when creating a reseller");
        }

        $client = $this->getClient();

        $planRequest = [
            'get' => [
                'filter' => [
                    'name' => $plan
                ]
            ]
        ];

        try {
            $plan = $client->resellerPlan()->request($planRequest);
        } catch (PleskException | PleskClientException | ProviderError $e) {
            return $this->handleException($e, 'Get reseller plan info');
        }

        $resellerRequest = [
            'add' => [
                'gen-info' => compact('pname', 'login', 'passwd', 'email'),
                'plan-id' => $plan->id
            ]
        ];

        try {
            //create reseller
            $customer = $client->reseller()->request($resellerRequest);
        } catch (PleskException | PleskClientException | ProviderError $e) {
            return $this->handleException($e, 'Create reseller');
        }

        if (!$ip_address) {
            try {
                //get a shared ip to use
                foreach ($client->ip()->get() as $ipInfo) {
                    if ($ipInfo->type === 'shared') {
                        $ip_address = $ipInfo->ipAddress;
                        break;
                    }
                }

                if (!$ip_address) {
                    throw new PleskException("Plesk server has no shared IPs");
                }
            } catch (PleskException | PleskClientException | ProviderError $e) {
                //cleanup reseller
                $client->reseller()->delete('id', $customer->id);

                return $this->handleException($e, 'Get IPs');
            } catch (Throwable $e) {
                //cleanup reseller
                $client->reseller()->delete('id', $customer->id);
                //let ProviderJob object handle this one
                throw $e;
            }
        }

        // try {
        //     //assign ip
        //     $resellerRequest = [
        //         'ippool-set-ip' => [
        //             'reseller-id' => $customer->id,
        //             'filter' => [
        //                 'ip-address' => $ip_address,
        //             ]
        //         ]
        //     ];

        //     $client->reseller()->request($resellerRequest);

        // } catch (PleskException | PleskClientException | ProviderError $e) {
        //     //cleanup reseller
        //     $client->reseller()->delete('id', $customer->id);

        //     return $this->handleException($e, 'Assign ip address');
        // } catch (Throwable $e) {
        //     //cleanup reseller
        //     $client->reseller()->delete('id', $customer->id);
        //     //let ProviderJob object handle this one
        //     throw $e;
        // }

        try {
            //create webspace
            $webspaceParams = [
                'name' => $domain,
                'owner-id' => $customer->id,
                'ip_address' => $ip_address,
                'htype' => 'vrt_hst'
            ];
            $hostingParams = [
                'ftp_login' => $login,
                'ftp_password' => $passwd
            ];
            $webspace = $client->webspace()->create($webspaceParams, $hostingParams);
        } catch (PleskException | PleskClientException | ProviderError $e) {
            //cleanup reseller
            $client->reseller()->delete('id', $customer->id);

            return $this->handleException($e, 'Create webspace');
        } catch (Throwable $e) {
            //cleanup reseller
            $client->reseller()->delete('id', $customer->id);
            //let ProviderJob object handle this one
            throw $e;
        }

        return $this->getInfo(new AccountUsername(['username' => $login]))
            ->setMessage('Reseller created')
            ->setDebug(@compact('customer', 'webspace'));
    }

    public function grantReseller(GrantResellerParams $params): ResellerPrivileges
    {
        $username = $params->username;
        // $plan = $params->package_name ?: 'Custom';
        $plan = 'Custom'; // plan quotas / settings don't change

        if ($this->loginBelongsToReseller($username)) {
            return ResellerPrivileges::create()
                ->setMessage('Account is already a reseller')
                ->setReseller(true);
        }

        if ($plan !== 'Custom') {
            try {
                $this->getPlan($plan, 'reseller'); //check reseller plan exists
            } catch (PleskException | PleskClientException | ProviderError $e) {
                return $this->handleException($e, 'Get reseller plan info');
            }
        }

        $customerRequest = [
            'convert-to-reseller' => [
                'filter' => [
                    'login' => $username
                ],
                'reseller-plan-name' => $plan
            ]
        ];

        $client = $this->getClient();

        try {
            $client->customer()->request($customerRequest);

            return ResellerPrivileges::create()
                ->setMessage('Reseller privileges granted')
                ->setReseller(true);
        } catch (PleskException | PleskClientException | ProviderError $e) {
            return $this->handleException($e, 'Grant reseller privileges');
        }
    }

    public function revokeReseller(AccountUsername $params): ResellerPrivileges
    {
        $username = $params->username;
        // $plan = $params->package_name ?: 'Custom';
        $plan = 'Custom'; // plan quotas / settings don't change

        if (! $this->loginBelongsToReseller($username)) {
            return ResellerPrivileges::create()
                ->setMessage('Account is already not a reseller')
                ->setReseller(false);
        }

        if ($plan !== 'Custom') {
            try {
                $this->getPlan($plan, 'service'); //check service plan exists
            } catch (PleskException | PleskClientException | ProviderError $e) {
                return $this->handleException($e, 'Get plan info');
            }
        }

        $resellerRequest = [
            'convert-to-customer' => [
                'filter' => [
                    'login' => $username
                ],
                'plan-name' => $plan
            ]
        ];

        $client = $this->getClient();

        try {
            $client->reseller()->request($resellerRequest);

            return ResellerPrivileges::create()
                ->setMessage('Reseller privileges revoked')
                ->setReseller(false);
        } catch (PleskException | PleskClientException | ProviderError $e) {
            return $this->handleException($e, 'Revoke reseller privileges');
        }
    }

    public function getInfo(AccountUsername $params): AccountInfo
    {
        $username = $params->username;

        if ($this->loginBelongsToReseller($username)) {
            return $this->getResellerInfo($username);
        }

        $client = $this->getClient();

        try {
            if ($params->domain) {
                // find webspace by domain
                $domainInfo = $this->getDomainInfo($client, $params->domain);
                $subscriptionId = $domainInfo->data->gen_info->getValue('webspace-id');
                $webspaceInfo = $this->getWebspaceInfo($client, $subscriptionId);
                $customerId = $webspaceInfo->data->gen_info->getValue('owner-id');

                $customerInfo = $this->getCustomerInfo($client, $customerId);
                $username = $customerInfo->data->gen_info->getValue('login');
                $ipAddress = $webspaceInfo->data->gen_info->getValue('dns_ip_address');
                $domainNameServers = [];
                try {
                    $domainNameServers = $this->getDnsRecords($client, $domainInfo->getValue('id'), 'NS');
                } catch (Throwable $e) {
                    if (!Str::contains($e->getMessage(), 'DNS service is not enabled')) {
                        throw $e;
                    }
                }

                if ($subscriptionPlan = $webspaceInfo->data->subscriptions->subscription->plan ?? null) {
                    $planInfo = $this->getPlanInfo($client, $subscriptionPlan->getValue('plan-guid'));
                    $planName = $planInfo->getValue('name');
                }

                return AccountInfo::create([
                    'customer_id' => $customerId,
                    'username' => $username,
                    'domain' => $domainInfo->data->gen_info->getValue('name'),
                    'reseller' => false,
                    'server_hostname' => $this->configuration->hostname,
                    'package_name' => $planName ?? 'Unknown',
                    'suspended' => (string)$webspaceInfo->data->gen_info->status !== '0',
                    'suspend_reason' => null,
                    'ip' => $ipAddress,
                    'nameservers' => $domainNameServers,
                ]);
            }

            $domainRequest = [
                'get-domain-list' => [
                    'filter' => [
                        'login' => $username,
                    ],
                ],
            ];

            $webspaceRequest = [
                'get' => [
                    'filter' => [
                        'owner-login' => $username,
                    ],
                    'dataset' => [
                        'gen_info' => '',
                        'stat' => '',
                        'hosting' => '',
                        'packages' => '',
                        'plan-items' => '',
                        'subscriptions' => '',
                    ],
                ],
            ];

            $domainInfo = $client->customer()->request($domainRequest, Client::RESPONSE_FULL);
            $domainInfo = json_decode(json_encode($domainInfo, JSON_PRETTY_PRINT), true);
            $webspaceInfo = $client->webspace()->request($webspaceRequest);
            $domainNameServers = [];

            try {
                $domainNameServers = $this->extractNameServers(
                    (string)$webspaceInfo->data->gen_info->name,
                    $domainInfo['customer']['get-domain-list']['result']['domains'],
                    $client
                );
            } catch (Throwable $e) {
                if (!Str::contains($e->getMessage(), 'DNS service is not enabled')) {
                    throw $e;
                }
            }

            $subscriptions = json_decode(json_encode($webspaceInfo->data->{'subscriptions'}, JSON_PRETTY_PRINT), true);
            $servicePlanRequest = [
                'get' => [
                    'filter' => [
                        'guid' => $subscriptions['subscription']['plan']['plan-guid'],
                    ],
                ],
            ];

            $servicePlanInfo = $client->servicePlan()->request($servicePlanRequest);

            return AccountInfo::create(
                [
                    'customer_id' => (string)$webspaceInfo->data->gen_info->{'owner-id'},
                    'username' => $username,
                    'domain' => (string)$webspaceInfo->data->gen_info->name,
                    'reseller' => false,
                    'server_hostname' => $this->configuration->hostname,
                    'package_name' => isset($servicePlanInfo->name) ? (string)$servicePlanInfo->name : 'Custom',
                    'suspended' => !((int)$webspaceInfo->data->gen_info->status === 0),
                    'suspend_reason' => null,
                    'ip' => (string)$webspaceInfo->data->gen_info->dns_ip_address,
                    'nameservers' => $domainNameServers,
                ]
            );
        } catch (PleskException | PleskClientException | ProviderError $e) {
            return $this->handleException($e, 'Get subscription info');
        }
    }

    protected function getResellerInfo(string $username): AccountInfo
    {
        $webspaceRequest = [
            'get' => [
                'filter' => [
                    'owner-login' => $username,
                ],
                'dataset' => [
                    'gen_info' => '',
                    'stat' => '',
                    'hosting' => '',
                    'packages' => '',
                    'plan-items' => '',
                    'subscriptions' => '',
                ],
            ],
        ];

        $domainRequest = [
            'get-domain-list' => [
                'filter' => [
                    'login' => $username,
                ],
            ],
        ];

        $client = $this->getClient();

        try {
            $webSpaceInfo = $client->webspace()->request($webspaceRequest);
            $domainInfo = $client->reseller()->request($domainRequest, Client::RESPONSE_FULL);
            $domainInfo = json_decode(json_encode($domainInfo, JSON_PRETTY_PRINT), true);
            $domainNameServers = [];

            try {
                $domainNameServers = $this->extractNameServers(
                    (string)$webSpaceInfo->data->gen_info->name,
                    $domainInfo['reseller']['get-domain-list']['result']['domains'],
                    $client
                );
            } catch (Throwable $e) {
                if (!Str::contains($e->getMessage(), 'DNS service is not enabled')) {
                    throw $e;
                }
            }

            return AccountInfo::create(
                [
                    // dont keep customer_id for now - bit of a rework required in order to allow multiple subscriptions
                    // 'customer_id' => (string)$webspaceInfo->data->gen_info->{'owner-id'},
                    'username' => $username,
                    'domain' => (string)$webSpaceInfo->data->gen_info->name,
                    'reseller' => true,
                    'server_hostname' => $this->configuration->hostname,
                    'package_name' => 'Reseller', // unclear where to get actual reseller plan name from
                    'suspended' => !((int)$webSpaceInfo->data->gen_info->status === 0),
                    'suspend_reason' => null,
                    'ip' => (string)$webSpaceInfo->data->gen_info->dns_ip_address,
                    'nameservers' => $domainNameServers,
                ]
            );
        } catch (PleskException | PleskClientException | ProviderError $e) {
            return $this->handleException($e, 'Get reseller info');
        }
    }

    public function getUsage(AccountUsername $params): AccountUsage
    {
        if ($params->is_reseller === true) {
            return $this->getResellerUsage($params);
        }

        if ($this->loginBelongsToReseller($params->username)) {
            $this->errorResult('Account is a reseller, cannot get usage as a standard account');
        }

        $result = $this->getClient()->webspace()->getAll();
        return AccountUsage::create()->setUsageData([]);
    }

    public function changePackage(ChangePackageParams $params): AccountInfo
    {
        $username = $params->username;
        $plan = $params->package_name;

        if ($this->loginBelongsToReseller($username)) {
            $this->changeResellerPackage($username, $plan);

            return $this->getInfo(AccountUsername::create($params))
                ->setMessage('Reseller package changed');
        }

        $client = $this->getClient();

        try {
            $plan = $this->getPlan($plan);
        } catch (PleskException | PleskClientException | ProviderError $e) {
            return $this->handleException($e, 'Get plan info');
        }

        $webspaceRequest = [
            'switch-subscription' => [
                'filter' => [
                    'owner-login' => $username
                ],
                'plan-guid' => $plan->guid
            ]
        ];

        if ($params->domain) {
            $webspaceRequest['switch-subscription']['filter'] = [
                'name' => $params->domain
            ];
        }

        try {
            $response = $client->webspace()->request($webspaceRequest);

            return $this->getInfo(AccountUsername::create($params))
                ->setMessage('Package changed');
        } catch (PleskException | PleskClientException | ProviderError $e) {
            return $this->handleException($e, "Change customer package");
        }
    }

    protected function changeResellerPackage(string $username, string $plan): EmptyResult
    {
        $client = $this->getClient();

        try {
            $plan = $this->getPlan($plan, 'reseller');
        } catch (PleskException | PleskClientException | ProviderError $e) {
            return $this->handleException($e, 'Get reseller plan info');
        }

        $webspaceRequest = [
            'switch-subscription' => [
                'filter' => [
                    'login' => $username
                ],
                'plan-guid' => $plan->guid
            ]
        ];

        try {
            $response = $client->reseller()->request($webspaceRequest);

            return $this->emptyResult("Reseller package changed");
        } catch (PleskException | PleskClientException | ProviderError $e) {
            return $this->handleException($e, "Change reseller package");
        }
    }

    public function getLoginUrl(GetLoginUrlParams $params): LoginUrl
    {
        $this->assertNotRoot($params->username);

        $username = $params->username;
        $user_ip = $params->user_ip;

        $client = $this->getClient();

        try {
            // if ($params->domain) {
            //     $webspaceInfo = $this->getDomainWebspaceInfo($client, $params->domain);

            //     if ((string)$webspaceInfo->data->gen_info->status == '0') {
            //         throw $this->errorResult('Webspace suspended', [
            //             'status' => (string)$webspaceInfo->data->gen_info->status,
            //             'webspace_guid' => $webspaceInfo->data->gen_info->getValue('guid')
            //         ]);
            //     }
            // }

            $sessionId = $client->server()->createSession($username, $user_ip);
            if ('windows' === $this->configuration->operating_system) {
                $sessionKey = 'PLESKSESSID';
            } else {
                // linux
                $sessionKey = 'PHPSESSID';
            }

            $url = $this->getServerUrl("/enterprise/rsession_init.php?{$sessionKey}={$sessionId}");

            return LoginUrl::create()
                ->setMessage('Session created')
                ->setLoginUrl($url)
                ->setForIp($user_ip)
                ->setExpires(Carbon::now()->addMinutes(30)); // default 30 minute session idle time
        } catch (PleskException | PleskClientException | ProviderError $e) {
            return $this->handleException($e, 'Create session');
        }
    }

    public function suspend(SuspendParams $params): AccountInfo
    {
        $username = $params->username;

        if ($this->loginBelongsToReseller($username)) {
            return $this->suspendReseller($username)
                ->setSuspendReason($params->reason);
        }

        $requestParams = [
            'set' => [
                'filter' => [
                    'login' => $username
                ],
                'values' => [
                    'gen_info' => [
                        // disabled by administrator - https://support.plesk.com/hc/en-us/articles/213902805
                        'status' => 16
                    ]
                ]
            ]
        ];

        $client = $this->getClient();

        try {
            if ($params->domain) {
                $requestParams = [
                    'set' => [
                        'filter' => [
                            'name' => $params->domain
                        ],
                        'values' => [
                            'gen_setup' => [
                                // disabled by administrator - https://support.plesk.com/hc/en-us/articles/213902805
                                'status' => 16
                            ]
                        ]
                    ]
                ];

                $client->webspace()->request($requestParams);
            } else {
                $client->customer()->request($requestParams);
            }

            return $this->getInfo(AccountUsername::create($params))
                ->setMessage('Subscription suspended')
                ->setSuspendReason($params->reason)
                ->setDebug($params->toArray());
        } catch (PleskException | PleskClientException | ProviderError $e) {
            return $this->handleException($e, 'Subscription suspension');
        }
    }

    protected function suspendReseller(string $username): AccountInfo
    {
        $requestParams = [
            'set' => [
                'filter' => [
                    'login' => $username
                ],
                'values' => [
                    'gen-info' => [
                        // disabled by administrator - https://support.plesk.com/hc/en-us/articles/213902805
                        'status' => 16
                    ]
                ]
            ]
        ];

        $client = $this->getClient();

        try {
            $client->reseller()->request($requestParams);

            return $this->getInfo(AccountUsername::create(['username' => $username]))
            ->setMessage('Reseller suspended');
        } catch (PleskException | PleskClientException | ProviderError $e) {
            return $this->handleException($e, 'Reseller suspension');
        }
    }

    public function unSuspend(AccountUsername $params): AccountInfo
    {
        $username = $params->username;

        if ($this->loginBelongsToReseller($username)) {
            return $this->unSuspendReseller($username);
        }

        $requestParams = [
            'set' => [
                'filter' => [
                    'login' => $username
                ],
                'values' => [
                    'gen_info' => [
                        'status' => 0 //active - https://support.plesk.com/hc/en-us/articles/213902805
                    ]
                ]
            ]
        ];

        $client = $this->getClient();

        try {
            if ($params->domain) {
                $requestParams = [
                    'set' => [
                        'filter' => [
                            'name' => $params->domain,
                        ],
                        'values' => [
                            'gen_setup' => [
                                //active - https://support.plesk.com/hc/en-us/articles/213902805
                                'status' => 0
                            ]
                        ]
                    ]
                ];

                $client->webspace()->request($requestParams);
            } else {
                $client->customer()->request($requestParams);
            }

            return $this->getInfo(AccountUsername::create($params))
                ->setMessage('Subscription unsuspended')
                ->setDebug($params->toArray());
        } catch (PleskException | PleskClientException | ProviderError $e) {
            return $this->handleException($e, 'Subscription unsuspension');
        }
    }

    public function unSuspendReseller(string $username): AccountInfo
    {
        $requestParams = [
            'set' => [
                'filter' => [
                    'login' => $username
                ],
                'values' => [
                    'gen-info' => [
                        'status' => 0 //active - https://support.plesk.com/hc/en-us/articles/213902805
                    ]
                ]
            ]
        ];

        $client = $this->getClient();

        try {
            $client->reseller()->request($requestParams);

            return $this->getInfo(AccountUsername::create(['username' => $username]))
            ->setMessage('Reseller unsuspended');
        } catch (PleskException | PleskClientException | ProviderError $e) {
            return $this->handleException($e, 'Reseller unsuspension');
        }
    }

    public function changePassword(ChangePasswordParams $params): EmptyResult
    {
        $this->assertNotRoot($params->username);

        $username = $params->username;
        $password = $params->password;

        if ($this->loginBelongsToReseller($username)) {
            return $this->changeResellerPassword($username, $password);
        }

        $requestParams = [
            'set' => [
                'filter' => [
                    'login' => $username
                ],
                'values' => [
                    'gen_info' => [
                        'passwd' => $password
                    ]
                ]
            ]
        ];

        $client = $this->getClient();

        try {
            $client->customer()->request($requestParams);

            return $this->emptyResult('Password changed');
        } catch (PleskException | PleskClientException | ProviderError $e) {
            return $this->handleException($e, 'Change password');
        }
    }

    public function changeResellerPassword(string $username, string $password): EmptyResult
    {
        $requestParams = [
            'set' => [
                'filter' => [
                    'login' => $username
                ],
                'values' => [
                    'gen-info' => [
                        'passwd' => $password
                    ]
                ]
            ]
        ];

        $client = $this->getClient();

        try {
            $client->reseller()->request($requestParams);

            return $this->emptyResult('Password changed');
        } catch (PleskException | PleskClientException | ProviderError $e) {
            return $this->handleException($e, 'Change password');
        }
    }

    public function terminate(AccountUsername $params): EmptyResult
    {
        $username = $params->username;

        if ($this->loginBelongsToReseller($username)) {
            return $this->terminateReseller($username);
        }

        $client = $this->getClient();

        try {
            if ($params->domain) {
                $client->webspace()->delete('name', $params->domain);
            } else {
                $client->customer()->delete('login', $username);
            }

            return $this->emptyResult('Subscription deleted');
        } catch (PleskException | PleskClientException | ProviderError $e) {
            return $this->handleException($e, 'Delete Subscription');
        }
    }

    public function terminateReseller(string $username): EmptyResult
    {
        $client = $this->getClient();

        try {
            $client->reseller()->delete('login', $username);

            return $this->emptyResult('Reseller deleted');
        } catch (PleskException | PleskClientException | ProviderError $e) {
            return $this->handleException($e, 'Delete reseller');
        }
    }

    /**
     * @param string $username
     */
    protected function assertNotRoot($username)
    {
        if (0 === strcasecmp(trim((string)$username), 'root')) {
            $this->errorResult('Cannot perform this action on root');
        }

        if (0 === strcasecmp(trim((string)$username), 'administrator')) {
            $this->errorResult('Cannot perform this action on root');
        }
    }

    /**
     * @param string $base Base string to generate a username from
     * @param int $count Number of attempts so far
     *
     * @return string A unique valid username
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
            $this->getMaxUsernameLength() - 1
        ) . rand(1, 9);

        return $username;

        // if ($this->newUsernameIsValid($username)) {
        //     return $username;
        // }

        $username = substr($username, 0, $this->getMaxUsernameLength() - 1) . rand(1, 9);

        return $this->generateUsername($username, $count++);
    }

    protected function getMaxUsernameLength(): int
    {
        return 8;
    }

    /**
     * @param string $username Login username
     *
     * @return bool
     */
    protected function loginBelongsToReseller(string $username): bool
    {
        $client = $this->getClient();

        try {
            $client->reseller()->get('login', $username); //throws api exception if login not a reseller

            return true;
        } catch (PleskException $e) {
            return false;
        }
    }

    /**
     * @param string $plan Id or Name of the plan
     * @param string $type Type of plan i.e., service or reseller
     *
     * @throws PleskException If plan doesn't exist
     *
     * @return XmlResponse
     */
    protected function getPlan(string $plan, string $type = 'service'): XmlResponse
    {
        $operator = strtolower($type) . 'Plan';

        $filter = is_numeric($plan)
            ? ['id' => $plan]
            : ['name' => $plan];

        $planRequest = [
            'get' => [
                'filter' => $filter,
            ]
        ];

        return $this->getClient()->$operator()->request($planRequest);
    }

    protected function getServerUrl(string $path = ''): string
    {
        $hostname = $this->configuration->hostname;
        $port = $this->configuration->port ?: 8443;
        $protocol = !empty($this->configuration->protocol) ? $this->configuration->protocol : 'https';
        $path = ltrim($path, '/');

        return "{$protocol}://{$hostname}:{$port}/{$path}";
    }

    /**
     * @throws ProvisionFunctionError
     *
     * @return no-return
     */
    protected function handleException(
        Throwable $e,
        string $failedOperation = 'XML API request',
        array $data = [],
        array $debugData = []
    ): void {
        if ($e instanceof ProvisionFunctionError) {
            $data = array_merge($e->getData(), $data);
            $debugData = array_merge($e->getDebug(), $debugData);
        }

        $this->errorResult($this->getErrorMessage($e, $failedOperation), $data, $debugData, $e);
    }

    protected function getErrorMessage(Throwable $e, string $failedOperation = 'XML API request'): string
    {
        $message = sprintf('%s failed', $failedOperation);

        if (!$e instanceof \PleskX\Api\Exception) {
            return $message;
        }

        $reason = str_replace("\n", ' ', $e->getMessage());

        if (Str::contains($reason, 'incorrect username or password')) {
            $reason = 'Invalid auth credentials';
        }

        if (Str::contains($reason, 'Parser error')) {
            $reason = 'Internal provider error';
        }

        return sprintf('%s: %s', $message, $reason);
    }

    protected function getClient(): Client
    {
        if ($this->client) {
            return $this->client;
        }

        $hostname = $this->configuration->hostname;
        $port = $this->configuration->port ?: 8443;
        $protocol = !empty($this->configuration->protocol) ? $this->configuration->protocol : 'https';

        $client = new Client($hostname, $port, $protocol);

        $admin_username = $this->configuration->admin_username;
        $admin_password = $this->configuration->admin_password;
        $secret_key = $this->configuration->secret_key;

        if ($secret_key) {
            $client->setSecretKey($secret_key);
        } else {
            $client->setCredentials($admin_username, $admin_password);
        }

        $client->setLogger($this->getLogger());

        return $this->client = $client;
    }

    /**
     * @param Client $client
     * @param int|string $domainId
     * @param string $type E.g., NS
     *
     * @return string[]
     */
    private function getDnsRecords(Client $client, $domainId, string $type): array
    {
        try {
            $dnsInfo = $client->dns()->request([
                'get_rec' => [
                    'filter' => [
                        'site-id' => $domainId,
                    ],
                    'include-subdomains' => ''
                ],
            ], Client::RESPONSE_FULL);

            $records = [];

            $dnsInfo = json_decode(json_encode($dnsInfo), true);
            foreach ($dnsInfo['dns']['get_rec']['result'] as $dns) {
                if ($dns['status'] == 'ok' && $dns['data']['type'] == $type) {
                    $records[] = rtrim($dns['data']['value'], '.');
                }
            }

            natsort($records);

            return array_values(array_unique($records));
        } catch (PleskException | PleskClientException | ProviderError $e) {
            return $this->handleException($e, 'Get dns records', ['domain_id' => $domainId, 'type' => $type]);
        }
    }

    /**
     * @param array $domains
     * @param Client $client
     * @param array $domainNameServers
     * @return array
     */
    private function extractNameServers(
        string $domainName,
        array $domains,
        \PleskX\Api\Client $client,
        array $domainNameServers = []
    ): array {
        foreach ($domains as $domain) {
            if (!isset($domain['id'])) {
                $domainNameServers = $this->extractNameServers($domainName, $domain, $client, $domainNameServers);
                continue;
            }

            if (!$domain['main']) {
                continue;
            }

            if ($domainName != $domain['name']) {
                continue;
            }

            $domainNameServers = array_merge(
                $domainNameServers ?? [],
                $this->getDnsRecords($client, $domain['id'], 'NS')
            );
        }

        natsort($domainNameServers);

        return array_values(array_unique($domainNameServers));
    }

    private function getDomainInfo(Client $client, string $domain): XmlResponse
    {
        try {
            return $client->site()->request([
                'get' => [
                    'filter' => [
                        'name' => $domain,
                    ],
                    'dataset' => [
                        'gen_info' => '',
                        'hosting' => '',
                        'stat' => '',
                        'prefs' => '',
                        'disk_usage' => '',
                    ],
                ],
            ]);
        } catch (PleskException | PleskClientException | ProviderError $e) {
            return $this->handleException($e, 'Get domain info', ['domain' => $domain]);
        }
    }

    private function getDomainWebspaceInfo(Client $client, string $domain): XmlResponse
    {
        $domainInfo = $this->getDomainInfo($client, $domain);

        return $this->getWebspaceInfo($client, $domainInfo->data->gen_info->getValue('webspace-id'));
    }

    private function getWebspaceInfo(Client $client, $webspaceId, string $type = 'id'): XmlResponse
    {
        try {
            return $client->webspace()->request([
                'get' => [
                    'filter' => [
                        $type => $webspaceId,
                    ],
                    'dataset' => [
                        'gen_info' => '',
                        'stat' => '',
                        'hosting' => '',
                        'packages' => '',
                        'plan-items' => '',
                        'subscriptions' => '',
                    ],
                ],
            ]);
        } catch (PleskException | PleskClientException | ProviderError $e) {
            return $this->handleException($e, 'Get customer info', [$type => $webspaceId]);
        }
    }

    private function getCustomerInfo(Client $client, $ownerId): XmlResponse
    {
        try {
            return $client->customer()->request([
                'get' => [
                    'filter' => [
                        'id' => $ownerId,
                    ],
                    'dataset' => [
                        'gen_info' => '',
                        'stat' => '',
                    ],
                ],
            ]);
        } catch (PleskException | PleskClientException | ProviderError $e) {
            return $this->handleException($e, 'Get customer info', ['customer_id' => $ownerId]);
        }
    }

    private function getPlanInfo(Client $client, $planGuid): XmlResponse
    {
        try {
            return $client->servicePlan()->request([
                'get' => [
                    'filter' => [
                        'guid' => $planGuid,
                    ],
                ],
            ]);
        } catch (PleskException | PleskClientException | ProviderError $e) {
            return $this->handleException($e, 'Get plan info', ['plan_guid' => $planGuid]);
        }
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    private function getResellerUsage(): AccountUsage
    {
        return AccountUsage::create()->setMessage('Reseller usage not implemented');
    }
}
