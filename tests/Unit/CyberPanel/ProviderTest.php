<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\Tests\Unit\CyberPanel;

use Upmind\ProvisionProviders\SharedHosting\CyberPanel\Data\Configuration;
use Upmind\ProvisionProviders\SharedHosting\CyberPanel\Provider;
use Upmind\ProvisionProviders\SharedHosting\Data\AccountUsername;
use Upmind\ProvisionProviders\SharedHosting\Data\ChangePackageParams;
use Upmind\ProvisionProviders\SharedHosting\Data\ChangePasswordParams;
use Upmind\ProvisionProviders\SharedHosting\Data\ChangePrimaryDomainParams;
use Upmind\ProvisionProviders\SharedHosting\Data\CreateParams;
use Upmind\ProvisionProviders\SharedHosting\Data\GetLoginUrlParams;
use Upmind\ProvisionProviders\SharedHosting\Data\GrantResellerParams;
use Upmind\ProvisionProviders\SharedHosting\Data\SuspendParams;

class ProviderTest extends CyberPanelTestCase
{
    private function makeProvider(?Configuration $configuration = null): TestableProvider
    {
        $configuration = $configuration ?: $this->makeConfiguration();

        return new TestableProvider($configuration, $this->makeApi($configuration));
    }

    public function testAboutProvider(): void
    {
        $about = Provider::aboutProvider();
        $about->autoValidation(false);

        $this->assertSame('CyberPanel', $about->name);
        $this->assertNotEmpty($about->description);
        $this->assertNotEmpty($about->logo_url);
    }

    // create

    public function testCreateWithGivenCredentials(): void
    {
        $this->queueJson(['Default', 'Pro'], ['createWebSiteStatus' => 1]);

        $result = $this->makeProvider()->create(CreateParams::create([
            'domain' => 'example.com',
            'email' => 'owner@example.com',
            'package_name' => 'Pro',
            'username' => 'bob',
            'password' => 'P4ssword!',
        ], false));

        $this->assertSame(['listPackage', 'createWebsite'], $this->calledFunctions());

        $payload = $this->requestPayload(1);
        $this->assertSame('bob', $payload['websiteOwner']);
        $this->assertSame('P4ssword!', $payload['ownerPassword']);
        $this->assertSame('Pro', $payload['packageName']);
        $this->assertSame('example.com', $payload['domainName']);
        $this->assertSame('owner@example.com', $payload['ownerEmail']);

        $this->assertSame([
            'username' => 'bob',
            'domain' => 'example.com',
            'package_name' => 'Pro',
            'suspended' => false,
            'reseller' => false,
            'server_hostname' => 'cp.example.com',
        ], $this->resultValues($result));
        $this->assertSame('Account created', $result->getMessage());
    }

    public function testCreateGeneratesUsernameAndPasswordWhenMissing(): void
    {
        $this->queueJson(['Default'], ['createWebSiteStatus' => 1]);

        $result = $this->makeProvider()->create(CreateParams::create([
            'domain' => 'my-site.example.com',
            'email' => 'owner@example.com',
            'package_name' => 'Default',
        ], false));

        $payload = $this->requestPayload(1);
        $this->assertMatchesRegularExpression('/^mysite\d{1,2}$/', $payload['websiteOwner']);
        $this->assertIsString($payload['ownerPassword']);
        $this->assertSame(15, strlen($payload['ownerPassword']));

        $this->assertSame($payload['websiteOwner'], $this->resultValues($result)['username']);
    }

    /**
     * @dataProvider createMissingFieldProvider
     *
     * @param array<string, string> $params
     */
    public function testCreateRequiresFields(array $params, string $expectedMessage): void
    {
        $error = $this->catchProvisionError(function () use ($params) {
            $this->makeProvider()->create(CreateParams::create($params, false));
        });

        $this->assertSame($expectedMessage, $error->getMessage());
        $this->assertSame([], $this->history, 'No API calls should be made');
    }

    /**
     * @return array<string, array<int, mixed>>
     */
    public static function createMissingFieldProvider(): array
    {
        return [
            'no domain' => [
                ['email' => 'owner@example.com', 'package_name' => 'Default'],
                'Domain name is required',
            ],
            'no package' => [
                ['domain' => 'example.com', 'email' => 'owner@example.com'],
                'Package name is required',
            ],
        ];
    }

    public function testCreateFailsWhenPackageDoesNotExist(): void
    {
        $this->queueJson(['Default']);

        $error = $this->catchProvisionError(function () {
            $this->makeProvider()->create(CreateParams::create([
                'domain' => 'example.com',
                'email' => 'owner@example.com',
                'package_name' => 'Missing',
            ], false));
        });

        $this->assertSame('The requested package does not exist on the server', $error->getMessage());
        $this->assertSame(['listPackage'], $this->calledFunctions(), 'Website must not be created');
    }

    public function testCreateFailsWhenPanelRejects(): void
    {
        $this->queueJson(['Default'], ['createWebSiteStatus' => 0, 'error_message' => 'Domain exists']);

        $error = $this->catchProvisionError(function () {
            $this->makeProvider()->create(CreateParams::create([
                'domain' => 'example.com',
                'email' => 'owner@example.com',
                'package_name' => 'Default',
            ], false));
        });

        $this->assertSame('Failed to create hosting account', $error->getMessage());
    }

    // getInfo

    public function testGetInfoWithDomain(): void
    {
        $this->queueJson(['status' => 1]);

        $result = $this->makeProvider()->getInfo(AccountUsername::create([
            'username' => 'bob',
            'domain' => 'example.com',
        ], false));

        $this->assertSame(['getUserInfo'], $this->calledFunctions());
        $this->assertSame('bob', $this->requestPayload(0)['username']);

        $values = $this->resultValues($result);
        $this->assertSame('bob', $values['username']);
        $this->assertSame('example.com', $values['domain']);
        $this->assertSame('cp.example.com', $values['server_hostname']);
        $this->assertSame('Hosting Account', $values['package_name']);
        $this->assertFalse($values['suspended']);
        $this->assertFalse($values['reseller']);
    }

    public function testGetInfoWithoutDomainOmitsDomain(): void
    {
        $this->queueJson(['status' => 1]);

        $result = $this->makeProvider()->getInfo(AccountUsername::create(['username' => 'bob'], false));

        $this->assertArrayNotHasKey('domain', $this->resultValues($result));
    }

    public function testGetInfoFailsWhenAccountMissing(): void
    {
        $this->queueJson(['status' => 0, 'error_message' => 'User does not exist']);

        $error = $this->catchProvisionError(function () {
            $this->makeProvider()->getInfo(AccountUsername::create(['username' => 'ghost'], false));
        });

        $this->assertSame('Account not found', $error->getMessage());
    }

    // getLoginUrl

    public function testGetLoginUrlReturnsPanelUrlWithCredentials(): void
    {
        $result = $this->makeProvider()->getLoginUrl(GetLoginUrlParams::create([
            'username' => 'bob',
            'current_password' => 'P4ssword!',
            'user_ip' => '203.0.113.5',
        ], false));

        $values = $this->resultValues($result);
        $this->assertSame('https://cp.example.com:8090/', $values['login_url']);
        $this->assertSame('203.0.113.5', $values['for_ip']);
        $this->assertNull($values['expires']);
        $this->assertSame(['username' => 'bob', 'password' => 'P4ssword!'], $values['post_fields']);
        $this->assertSame([], $this->history, 'No API calls should be made');
    }

    public function testGetLoginUrlChangesPasswordWhenNotProvided(): void
    {
        $this->queueJson(['changeStatus' => 1]);

        $result = $this->makeProvider()->getLoginUrl(GetLoginUrlParams::create([
            'username' => 'bob',
            'user_ip' => '203.0.113.5',
        ], false));

        $this->assertSame(['changeUserPassAPI'], $this->calledFunctions());
        $payload = $this->requestPayload(0);
        $this->assertSame('bob', $payload['websiteOwner']);
        $this->assertIsString($payload['ownerPassword']);
        $this->assertSame(15, strlen($payload['ownerPassword']));

        $values = $this->resultValues($result);
        $this->assertSame('https://cp.example.com:8090/', $values['login_url']);
        $this->assertSame(
            ['username' => 'bob', 'password' => $payload['ownerPassword']],
            $values['post_fields'],
            'Login must use the newly generated password'
        );
    }

    // changePassword

    public function testChangePassword(): void
    {
        $this->queueJson(['changeStatus' => 1]);

        $result = $this->makeProvider()->changePassword(ChangePasswordParams::create([
            'username' => 'bob',
            'password' => 'N3wPassword!',
        ], false));

        $this->assertSame(['changeUserPassAPI'], $this->calledFunctions());
        $this->assertSame('bob', $this->requestPayload(0)['websiteOwner']);
        $this->assertSame('N3wPassword!', $this->requestPayload(0)['ownerPassword']);
        $this->assertSame('Password changed', $result->getMessage());
    }

    // changePackage

    public function testChangePackage(): void
    {
        $this->queueJson(['Default', 'Pro'], ['changePackage' => 1]);

        $result = $this->makeProvider()->changePackage(ChangePackageParams::create([
            'username' => 'bob',
            'domain' => 'example.com',
            'package_name' => 'Pro',
        ], false));

        $this->assertSame(['listPackage', 'changePackageAPI'], $this->calledFunctions());
        $this->assertSame('example.com', $this->requestPayload(1)['websiteName']);
        $this->assertSame('Pro', $this->requestPayload(1)['packageName']);

        $values = $this->resultValues($result);
        $this->assertSame('bob', $values['username']);
        $this->assertSame('example.com', $values['domain']);
        $this->assertSame('Pro', $values['package_name']);
        $this->assertSame('Package changed', $result->getMessage());
    }

    public function testChangePackageRequiresDomain(): void
    {
        $error = $this->catchProvisionError(function () {
            $this->makeProvider()->changePackage(ChangePackageParams::create([
                'username' => 'bob',
                'package_name' => 'Pro',
            ], false));
        });

        $this->assertSame('Domain name is required for this operation', $error->getMessage());
        $this->assertSame([], $this->history);
    }

    public function testChangePackageRequiresPackageName(): void
    {
        $error = $this->catchProvisionError(function () {
            $this->makeProvider()->changePackage(ChangePackageParams::create([
                'username' => 'bob',
                'domain' => 'example.com',
            ], false));
        });

        $this->assertSame('Package name is required', $error->getMessage());
        $this->assertSame([], $this->history);
    }

    public function testChangePackageFailsWhenPackageDoesNotExist(): void
    {
        $this->queueJson(['Default']);

        $error = $this->catchProvisionError(function () {
            $this->makeProvider()->changePackage(ChangePackageParams::create([
                'username' => 'bob',
                'domain' => 'example.com',
                'package_name' => 'Missing',
            ], false));
        });

        $this->assertSame('The requested package does not exist on the server', $error->getMessage());
        $this->assertSame(['listPackage'], $this->calledFunctions());
    }

    // suspend / unsuspend

    public function testSuspend(): void
    {
        $this->queueJson(['websiteStatus' => 1]);

        $result = $this->makeProvider()->suspend(SuspendParams::create([
            'username' => 'bob',
            'domain' => 'example.com',
            'reason' => 'Overdue invoice',
        ], false));

        $this->assertSame(['submitWebsiteStatus'], $this->calledFunctions());
        $this->assertSame('Suspend', $this->requestPayload(0)['state']);
        $this->assertSame('example.com', $this->requestPayload(0)['websiteName']);

        $values = $this->resultValues($result);
        $this->assertTrue($values['suspended']);
        $this->assertSame('Overdue invoice', $values['suspend_reason']);
        $this->assertSame('Account suspended', $result->getMessage());
    }

    public function testUnSuspend(): void
    {
        $this->queueJson(['websiteStatus' => 1]);

        $result = $this->makeProvider()->unSuspend(AccountUsername::create([
            'username' => 'bob',
            'domain' => 'example.com',
        ], false));

        $this->assertSame(['submitWebsiteStatus'], $this->calledFunctions());
        $this->assertSame('Activate', $this->requestPayload(0)['state']);
        $this->assertFalse($this->resultValues($result)['suspended']);
        $this->assertSame('Account unsuspended', $result->getMessage());
    }

    // terminate

    public function testTerminate(): void
    {
        $this->queueJson(['websiteDeleteStatus' => 1]);

        $result = $this->makeProvider()->terminate(AccountUsername::create([
            'username' => 'bob',
            'domain' => 'example.com',
        ], false));

        $this->assertSame(['deleteWebsite'], $this->calledFunctions());
        $this->assertSame('example.com', $this->requestPayload(0)['domainName']);
        $this->assertSame('Account deleted', $result->getMessage());
    }

    public function testTerminateFailure(): void
    {
        $this->queueJson(['websiteDeleteStatus' => 0, 'error_message' => 'Website not found']);

        $error = $this->catchProvisionError(function () {
            $this->makeProvider()->terminate(AccountUsername::create([
                'username' => 'bob',
                'domain' => 'example.com',
            ], false));
        });

        $this->assertSame('Failed to delete hosting account', $error->getMessage());
    }

    /**
     * @dataProvider domainRequiredProvider
     */
    public function testDomainCentricOperationsRequireDomain(string $method, string $paramsClass): void
    {
        $provider = $this->makeProvider();
        $params = call_user_func([$paramsClass, 'create'], ['username' => 'bob'], false);

        $error = $this->catchProvisionError(function () use ($provider, $method, $params) {
            $provider->{$method}($params);
        });

        $this->assertSame('Domain name is required for this operation', $error->getMessage());
        $this->assertSame([], $this->history, 'No API calls should be made');
    }

    /**
     * @return array<string, array<int, string>>
     */
    public static function domainRequiredProvider(): array
    {
        return [
            'suspend' => ['suspend', SuspendParams::class],
            'unSuspend' => ['unSuspend', AccountUsername::class],
            'terminate' => ['terminate', AccountUsername::class],
        ];
    }

    // unsupported operations

    /**
     * @dataProvider unsupportedOperationProvider
     */
    public function testUnsupportedOperations(string $method, string $paramsClass): void
    {
        $provider = $this->makeProvider();
        $params = call_user_func([$paramsClass, 'create'], ['username' => 'bob'], false);

        $error = $this->catchProvisionError(function () use ($provider, $method, $params) {
            $provider->{$method}($params);
        });

        $this->assertSame('Operation not supported', $error->getMessage());
        $this->assertSame([], $this->history, 'No API calls should be made');
    }

    /**
     * @return array<string, array<int, string>>
     */
    public static function unsupportedOperationProvider(): array
    {
        return [
            'getUsage' => ['getUsage', AccountUsername::class],
            'changePrimaryDomain' => ['changePrimaryDomain', ChangePrimaryDomainParams::class],
            'grantReseller' => ['grantReseller', GrantResellerParams::class],
            'revokeReseller' => ['revokeReseller', AccountUsername::class],
        ];
    }

    // helpers

    public function testControlPanelUrlWithPort(): void
    {
        $provider = $this->makeProvider($this->makeConfiguration(['port' => 8090]));

        $this->assertSame('https://cp.example.com:8090/', $provider->publicControlPanelUrl());
    }

    public function testControlPanelUrlWithoutPort(): void
    {
        $provider = $this->makeProvider($this->makeConfiguration(['port' => null]));

        $this->assertSame('https://cp.example.com/', $provider->publicControlPanelUrl());
    }

    /**
     * @dataProvider usernameProvider
     */
    public function testGenerateUsername(string $domain, string $expectedPrefix): void
    {
        $username = $this->makeProvider()->publicGenerateUsername($domain);

        $this->assertMatchesRegularExpression('/^' . preg_quote($expectedPrefix, '/') . '\d{1,2}$/', $username);
        $this->assertLessThanOrEqual(8, strlen($username));
    }

    /**
     * @return array<string, array<int, string>>
     */
    public static function usernameProvider(): array
    {
        return [
            'simple domain' => ['example.com', 'exampl'],
            'short domain' => ['ab.io', 'abio'],
            'uppercase' => ['EXAMPLE.COM', 'exampl'],
            'hyphens stripped' => ['my-site.com', 'mysite'],
            'leading digits stripped' => ['123abc.com', 'abccom'],
            'leading symbols and digits stripped' => ['1-2-3-go.net', 'gonet'],
        ];
    }
}
