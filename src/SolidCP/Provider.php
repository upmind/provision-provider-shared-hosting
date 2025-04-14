<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\SolidCP;

use Illuminate\Support\Arr;
use stdClass;
use Upmind\ProvisionBase\Helper;
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
use Upmind\ProvisionProviders\SharedHosting\SolidCP\Data\Configuration;

/**
 * SolidCP hosting provider template.
 */
class Provider extends Category implements ProviderInterface
{
    protected const ROLE_ADMIN = 1;
    protected const ROLE_RESELLER = 2;
    protected const ROLE_USER = 3;

    protected Configuration $configuration;
    protected Api $api;

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
            ->setName('SolidCP')
            ->setDescription('Create and manage windows shared hosting users and resellers with SolidCP')
            ->setLogoUrl('https://api.upmind.io/images/logos/provision/solidcp-logo.png');
    }

    public function getUsage(AccountUsername $params): AccountUsage
    {
        throw $this->errorResult('Operation not supported');
    }

    /**
     * @inheritDoc
     */
    public function create(CreateParams $params): AccountInfo
    {
        $username = $params->username ?? $this->generateUsername($params->domain);
        $name = $params->customer_name ?? explode('@', $params->email)[0];

        $plan = $this->findPlan($params->package_name);

        $client_params = [
            'parentPackageId' => $this->configuration->parent_space_id ?? 1,
            'username' => $username,
            'password' => $params->password ?? Helper::generateStrictPassword(15, true, true, false),
            'roleId' => $params->as_reseller ? self::ROLE_RESELLER : self::ROLE_USER,
            'firstName' => explode(" ", $name)[0],
            'lastName' => explode(" ", $name, 2)[1] ?? null,
            'email' => $params->email,
            'htmlMail' => false,
            'sendAccountLetter' => false,
            'createPackage' => true,
            'planId' => $plan->PlanId,
            'sendPackageLetter' => false,
            'domainName' => $params->domain,
            'tempDomain' => false,
            'createWebSite' => true,
            'createFtpAccount' => false,
            'createMailAccount' => false,
            'hostName' => '',
            'createZoneRecord' => true
        ];

        $this->api()->execute('Packages', 'CreateUserWizard', $client_params, 'CreateUserWizardResult');

        return $this->getInfoResult($username, $params->domain)->setMessage('Account created successfully');
    }

    /**
     * @inheritDoc
     */
    public function getInfo(AccountUsername $params): AccountInfo
    {
        return $this->getInfoResult($params->username, $params->domain);
    }

    /**
     * @inheritDoc
     */
    public function getLoginUrl(GetLoginUrlParams $params): LoginUrl
    {
        $this->assertNotRoot($params->username);

        $portalUrl = $this->configuration->portal_url;
        $password = $params->current_password;

        if (!array_key_exists('scheme', parse_url($portalUrl))) {
            $portalUrl = 'https://' . $portalUrl;
        }

        // If the password has not been provided, change the password to a random one.
        if (empty($password)) {
            $password = $this->generatePassword();
            $this->updateUserPassword($params->username, $password);
        }

        return LoginUrl::create()
            ->setLoginUrl(rtrim($portalUrl, '/') . '/Default.aspx?pid=Login')
            ->setPostFields([
                'user' => $params->username,
                'password' => $password
            ]);
    }

    /**
     * @return string
     */
    protected function generatePassword(): string
    {
        return Helper::generateStrictPassword(10, true, true, true);
    }

    /**
     * @param string $username
     * @param string $password
     * @return void
     */
    protected function updateUserPassword(string $username, string $password)
    {
        $userId = $this->getUserByUsername($username)->UserId;
        $client_params = ['username' => $username, 'password' => $password, 'userId' => $userId];
        $this->api()->execute(
            'Users',
            'ChangeUserPassword',
            $client_params,
            'ChangeUserPasswordResult'
        );
    }

    /**
     * @inheritDoc
     */
    public function changePassword(ChangePasswordParams $params): EmptyResult
    {
        $this->assertNotRoot($params->username);

        $this->updateUserPassword($params->username, $params->password);
        return $this->emptyResult('Password changed');
    }

    /**
     * @inheritDoc
     */
    public function changePackage(ChangePackageParams $params): AccountInfo
    {
        $package = $this->getPackagesByUsername($params->username);

        $client_params = [
            'packageId' => $package->PackageId,
            'statusId' => $package->StatusId,
            'planId' => $params->package_name,
            'purchaseDate' => $package->PurchaseDate,
            'packageName' => $params->package_name,
            'packageComments' => isset($package->packageComments) ? $package->packageComments : ''
        ];
        $this->api()->execute('Packages', 'UpdatePackageLiteral', $client_params, 'UpdatePackageLiteralResult');

        return $this->getInfoResult($params->username, $params->domain)
            ->setMessage('Package updated');
    }
    /**
     * @inheritDoc
     */
    public function suspend(SuspendParams $params): AccountInfo
    {
        $userId = $this->getUserByUsername($params->username)->UserId;
        $client_params = ['username' => $params->username, 'status' => 'Suspended', 'userId' => $userId];
        $this->api()->execute('Users', 'ChangeUserStatus', $client_params, 'ChangeUserStatusResult');

        return $this->getInfoResult($params->username, $params->domain)
            ->setSuspendReason($params->reason)
            ->setMessage('Account suspended');
    }
    /**
     * @inheritDoc
     */
    public function unSuspend(AccountUsername $params): AccountInfo
    {
        $userId = $this->getUserByUsername($params->username)->UserId;
        $client_params = ['username' => $params->username, 'status' => 'Active', 'userId' => $userId];
        $this->api()->execute('Users', 'ChangeUserStatus', $client_params, 'ChangeUserStatusResult');

        return $this->getInfoResult($params->username, $params->domain)
            ->setMessage('Account unsuspended');
    }
    /**
     * @inheritDoc
     */
    public function terminate(AccountUsername $params): EmptyResult
    {
        $userId = $this->getUserByUsername($params->username)->UserId;
        $client_params = ['username' => $params->username, 'userId' => $userId];
        $result = $this->api()->execute('Users', 'DeleteUser', $client_params, 'DeleteUserResult');

        return $this->emptyResult('User has been deleted');
    }

    /**
     * @inheritDoc
     */
    public function grantReseller(GrantResellerParams $params): ResellerPrivileges
    {
        return $this->changeReseller($params->username, self::ROLE_RESELLER, 'Reseller privileges granted');
    }

    /**
     * @inheritDoc
     */
    public function revokeReseller(AccountUsername $params): ResellerPrivileges
    {
        return $this->changeReseller($params->username, self::ROLE_USER, 'Reseller privileges revoked');
    }

    /**
     * @param int|string $planId
     */
    protected function findPlan($planId): stdClass
    {
        if (!is_numeric($planId)) {
            throw $this->errorResult('Package identifier must be a numeric plan ID');
        }

        $plan = $this->api()->execute('Packages', 'GetHostingPlan', ['planId' => $planId], 'GetHostingPlanResult');

        if (empty((array)$plan)) {
            throw $this->errorResult('Plan not found');
        }

        return $plan;
    }

    protected function getInfoResult(string $username, ?string $domainName = null): AccountInfo
    {
        $result = $this->getUserByUsername($username);
        $package = $this->getPackagesByUserId($result->UserId);

        $domains = $this->getDomainsByPackageId($package->PackageId);
        $domain = Arr::first($domains, function ($domain) use ($domainName) {
            return (is_null($domainName) || $domain->DomainName === $domainName)
                && !empty($domain->ZoneItemId);
        });
        if (isset($domain->ZoneItemId)) {
            if ($zoneRecords = $this->getDnsZoneRecords($domain->DomainId)) {
                $ip = Arr::first($zoneRecords, fn ($record) => $record->RecordType)->RecordData ?? null;
                $nameservers = collect($zoneRecords)
                    ->filter(fn ($record) => $record->RecordType === 'NS')
                    ->map(fn ($record) => $record->RecordData)
                    ->toArray();
            }
        }

        return AccountInfo::create([
            // 'customer_id' => (string) $result->UserId, // not used in subsequent calls / orders, so not needed
            'username' => $username,
            'domain' => $domain->DomainName ?? $domainName,
            'reseller' => $result->RoleId === self::ROLE_RESELLER,
            'server_hostname' => $this->configuration->portal_url,
            'package_name' => isset($package->PackageName) ? $package->PackageName : '',
            'suspended' => $result->Status === 'Suspended',
            'suspend_reason' => null,
            'ip' => $ip ?? null,
            'nameservers' => $nameservers ?? null,
        ]);
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
     * Generate a random username from the given domain name.
     */
    protected function generateUsername(string $domain): string
    {
        $username = preg_replace('/[^a-z0-9]/i', '', $domain);
        $username = substr($username, 0, 8);

        return $username . str_pad((string)random_int(1, 99), 2, '0', STR_PAD_LEFT);
    }

    protected function getUserByUsername(string $username): stdClass
    {
        $client_params = ['username' => $username];
        $result = $this->api()->execute('Users', 'GetUserByUsername', $client_params);

        if (empty((array)$result)) {
            throw $this->errorResult(Api::getFriendlyError('-101'));
        }

        return $result->GetUserByUsernameResult;
    }

    protected function getPackagesByUsername(string $username): stdClass
    {
        return $this->getPackagesByUserId((int)$this->getUserByUsername($username)->UserId);
    }

    protected function getPackagesByUserId(int $userId): stdClass
    {
        $client_params = ['userId' => $userId];
        $result = $this->api()->execute('Packages', 'GetMyPackages', $client_params, 'GetMyPackagesResult');

        if (empty((array)$result->PackageInfo)) {
            throw $this->errorResult(Api::getFriendlyError('-300'));
        }

        return $result->PackageInfo;
    }

    /**
     * @return stdClass[]
     */
    protected function getDomainsByPackageId(int $packageId): array
    {
        return $this->api()
            ->execute('Servers', 'GetDomains', ['packageId' => $packageId], 'GetDomainsResponse')
            ->GetDomainsResult
            ->DomainInfo ?? [];
    }

    /**
     * @return stdClass[]
     */
    protected function getDnsZoneRecords(int $domainId): array
    {
        return $this->api()
            ->execute('Servers', 'GetDnsZoneRecords', ['domainId' => $domainId], 'GetDnsZoneRecordsResponse')
            ->GetDnsZoneRecordsResult
            ->DnsRecord ?? [];
    }

    protected function changeReseller(string $username, int $roleId, string $message): ResellerPrivileges
    {
        $client_params = $this->getUserByUsername($username);
        $client_params->RoleId = $roleId;
        $client_params->Role = ($roleId == self::ROLE_RESELLER) ? 'Reseller' : 'User';

        $this->api()->execute('Users', 'UpdateUser', ['user' => $client_params], 'UpdateUserResult');

        return ResellerPrivileges::create()
            ->setMessage($message)
            ->setReseller($roleId === self::ROLE_RESELLER);
    }

    protected function api(): Api
    {
        return $this->api ??= new Api($this->configuration, $this->getLogger((bool)$this->configuration->debug));
    }
}
