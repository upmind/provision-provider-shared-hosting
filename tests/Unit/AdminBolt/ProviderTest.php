<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\Tests\Unit\AdminBolt;

use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Psr7\Request;
use Upmind\ProvisionProviders\SharedHosting\AdminBolt\Provider;
use Upmind\ProvisionProviders\SharedHosting\Data\AccountUsername;
use Upmind\ProvisionProviders\SharedHosting\Data\ChangePackageParams;
use Upmind\ProvisionProviders\SharedHosting\Data\ChangePasswordParams;
use Upmind\ProvisionProviders\SharedHosting\Data\ChangePrimaryDomainParams;
use Upmind\ProvisionProviders\SharedHosting\Data\CreateParams;
use Upmind\ProvisionProviders\SharedHosting\Data\GetLoginUrlParams;
use Upmind\ProvisionProviders\SharedHosting\Data\GrantResellerParams;
use Upmind\ProvisionProviders\SharedHosting\Data\SuspendParams;

class ProviderTest extends AdminBoltTestCase
{
    public function testAboutProvider(): void
    {
        $about = Provider::aboutProvider();
        $about->autoValidation(false);

        $this->assertSame('AdminBolt', $about->name);
        $this->assertNotEmpty($about->description);
        $this->assertNotEmpty($about->logo_url);
    }

    // client

    public function testClientUsesAdminApiByDefault(): void
    {
        $provider = new TestableProvider($this->makeConfiguration(), new \GuzzleHttp\Client());
        $config = $provider->realClient()->getConfig();

        $this->assertSame('https://panel.example.com:8443/api/', (string) $config['base_uri']);
        $this->assertSame('key', $config['headers']['X-API-Key']);
        $this->assertSame('secret', $config['headers']['X-API-Secret']);
        $this->assertTrue($config['verify']);
    }

    public function testClientUsesResellerApiPortAndSslOption(): void
    {
        $provider = new TestableProvider($this->makeConfiguration([
            'port' => 2087,
            'use_reseller_api' => true,
            'ignore_ssl_errors' => true,
        ]), new \GuzzleHttp\Client());
        $config = $provider->realClient()->getConfig();

        $this->assertSame('https://panel.example.com:2087/api/reseller/', (string) $config['base_uri']);
        $this->assertFalse($config['verify']);
    }

    // create

    public function testCreateSendsPlanByNameAndReturnsAccount(): void
    {
        $this->queue(201, ['id' => 7, 'hostingAccount' => $this->account()]);
        $this->queue(200, ['id' => 3, 'name' => 'Pro']);

        $result = $this->makeProvider()->create(CreateParams::create([
            'domain' => 'example.com',
            'email' => 'owner@example.com',
            'package_name' => 'Pro',
            'username' => 'bob',
            'password' => 'S3cure-Pass',
        ], false));

        $this->assertSame([
            'POST /api/hosting-accounts',
            'GET /api/hosting-plans/3',
        ], $this->calls());
        $this->assertSame([
            'domain' => 'example.com',
            'hosting_plan' => 'Pro',
            'username' => 'bob',
            'password' => 'S3cure-Pass',
            'email' => 'owner@example.com',
        ], $this->requestPayload(0));

        $values = $this->resultValues($result);
        $this->assertSame('bob', $values['username']);
        $this->assertSame('example.com', $values['domain']);
        $this->assertSame('Pro', $values['package_name']);
        $this->assertSame('7', $values['customer_id']);
        $this->assertSame('panel.example.com', $values['server_hostname']);
        $this->assertFalse($values['suspended']);
        $this->assertSame('Account created', $result->getMessage());
        $this->assertSame('[redacted]', $result->getDebug()['account']['sso_token']);
    }

    public function testCreateLeavesOutEmptyUsernameAndPassword(): void
    {
        $this->queue(201, ['id' => 7, 'hostingAccount' => $this->account(['username' => 'exampl1a2b'])]);
        $this->queue(200, ['id' => 3, 'name' => 'Pro']);

        $result = $this->makeProvider()->create(CreateParams::create([
            'domain' => 'example.com',
            'email' => 'owner@example.com',
            'package_name' => 'Pro',
        ], false));

        $this->assertSame([
            'domain' => 'example.com',
            'hosting_plan' => 'Pro',
            'email' => 'owner@example.com',
        ], $this->requestPayload(0));
        $this->assertSame('exampl1a2b', $this->resultValues($result)['username']);
    }

    public function testCreateReportsWarning(): void
    {
        $this->queue(201, ['id' => 7, 'hostingAccount' => $this->account(), 'warning' => 'SSL could not be issued']);
        $this->queue(200, ['id' => 3, 'name' => 'Pro']);

        $result = $this->makeProvider()->create(CreateParams::create([
            'domain' => 'example.com',
            'email' => 'owner@example.com',
            'package_name' => 'Pro',
        ], false));

        $this->assertSame('Account created with a warning: SSL could not be issued', $result->getMessage());
    }

    public function testCreatePassesValidationMessage(): void
    {
        $this->queue(422, ['message' => 'Hosting plan not found: Gold']);

        $error = $this->catchProvisionError(function () {
            $this->makeProvider()->create(CreateParams::create([
                'domain' => 'example.com',
                'email' => 'owner@example.com',
                'package_name' => 'Gold',
            ], false));
        });

        $this->assertSame('Failed to create account: Hosting plan not found: Gold', $error->getMessage());
        $this->assertSame(['http_status' => 422], $error->getData());
    }

    public function testCreateHidesServerErrorDetails(): void
    {
        $this->queue(500, ['message' => 'SQLSTATE[HY000] internal details']);

        $error = $this->catchProvisionError(function () {
            $this->makeProvider()->create(CreateParams::create([
                'domain' => 'example.com',
                'email' => 'owner@example.com',
                'package_name' => 'Pro',
            ], false));
        });

        $this->assertSame('Failed to create account', $error->getMessage());
        $this->assertSame('SQLSTATE[HY000] internal details', $error->getDebug()['response']['message']);
    }

    public function testCreateRequiresDomain(): void
    {
        $error = $this->catchProvisionError(function () {
            $this->makeProvider()->create(CreateParams::create([
                'email' => 'owner@example.com',
                'package_name' => 'Pro',
            ], false));
        });

        $this->assertSame('A domain name is required to create a hosting account', $error->getMessage());
        $this->assertSame([], $this->history);
    }

    public function testCreateResellerIsNotSupported(): void
    {
        $error = $this->catchProvisionError(function () {
            $this->makeProvider()->create(CreateParams::create([
                'domain' => 'example.com',
                'email' => 'owner@example.com',
                'package_name' => 'Pro',
                'as_reseller' => true,
            ], false));
        });

        $this->assertSame('Creating reseller accounts is not supported', $error->getMessage());
        $this->assertSame([], $this->history);
    }

    // getInfo

    public function testGetInfoLooksUpExactUsername(): void
    {
        // Older panels ignore the username filter and return every account.
        $this->queueLookup(
            $this->account(['id' => 6, 'username' => 'bobby']),
            $this->account(['is_suspended' => true])
        );
        $this->queue(200, ['id' => 3, 'name' => 'Pro']);

        $result = $this->makeProvider()->getInfo(AccountUsername::create(['username' => 'bob'], false));

        $this->assertSame([
            'GET /api/hosting-accounts?username=bob',
            'GET /api/hosting-plans/3',
        ], $this->calls());

        $values = $this->resultValues($result);
        $this->assertSame('7', $values['customer_id']);
        $this->assertTrue($values['suspended']);
    }

    public function testGetInfoAccountNotFound(): void
    {
        $this->queueLookup();

        $error = $this->catchProvisionError(function () {
            $this->makeProvider()->getInfo(AccountUsername::create(['username' => 'bob'], false));
        });

        $this->assertSame('Account not found', $error->getMessage());
    }

    public function testGetInfoFallsBackToPlanId(): void
    {
        $this->queueLookup($this->account());
        $this->queue(404, ['message' => 'Not found']);

        $result = $this->makeProvider()->getInfo(AccountUsername::create(['username' => 'bob'], false));

        $this->assertSame('3', $this->resultValues($result)['package_name']);
    }

    public function testAuthenticationFailure(): void
    {
        $this->queue(401, ['error' => 'Invalid API key or secret']);

        $error = $this->catchProvisionError(function () {
            $this->makeProvider()->getInfo(AccountUsername::create(['username' => 'bob'], false));
        });

        $this->assertSame(
            'Failed to look up account: authentication with the hosting server failed',
            $error->getMessage()
        );
    }

    public function testConnectionFailure(): void
    {
        $this->mockHandler->append(
            new ConnectException('cURL error 7: Failed to connect', new Request('GET', 'hosting-accounts'))
        );

        $error = $this->catchProvisionError(function () {
            $this->makeProvider()->getInfo(AccountUsername::create(['username' => 'bob'], false));
        });

        $this->assertSame('Unable to connect to the hosting server', $error->getMessage());
        $this->assertInstanceOf(ConnectException::class, $error->getPrevious());
    }

    // getUsage

    public function testGetUsage(): void
    {
        $this->queueLookup($this->account());
        $this->queue(200, ['usageDetails' => [
            'diskUsage' => 120.5,
            'totalDiskUsage' => 1024,
            'bandwidth' => '1,024.50 MB',
            'totalBandwidth' => 0,
            'emailAccounts' => 2,
            'totalEmailAccounts' => 10,
        ]]);

        $result = $this->makeProvider()->getUsage(AccountUsername::create(['username' => 'bob'], false));

        $this->assertSame('GET /api/hosting-accounts/7/usage-details', $this->calls()[1]);

        $usage = $this->resultValues($result)['usage_data'];
        $this->assertEquals(120.5, $usage['disk_mb']['used']);
        $this->assertEquals(1024, $usage['disk_mb']['limit']);
        $this->assertEquals(1024.5, $usage['bandwidth_mb']['used']);
        $this->assertNull($usage['bandwidth_mb']['limit']);
        $this->assertEquals(2, $usage['mailboxes']['used']);
        $this->assertEquals(10, $usage['mailboxes']['limit']);
    }

    // getLoginUrl

    public function testGetLoginUrl(): void
    {
        $this->queueLookup($this->account());
        $this->queue(200, ['sso_url' => 'https://panel.example.com:8443/sso-login/abc']);

        $result = $this->makeProvider()->getLoginUrl(GetLoginUrlParams::create([
            'username' => 'bob',
            'user_ip' => '203.0.113.5',
        ], false));

        $this->assertSame('POST /api/hosting-accounts/7/generate-sso-token', $this->calls()[1]);
        $values = $this->resultValues($result);
        $this->assertSame('https://panel.example.com:8443/sso-login/abc', $values['login_url']);
        $this->assertNotEmpty($values['expires']);
    }

    // changePassword

    public function testChangePassword(): void
    {
        $this->queueLookup($this->account());
        $this->queue(200, ['status' => 'success', 'message' => 'Password changed']);

        $result = $this->makeProvider()->changePassword(ChangePasswordParams::create([
            'username' => 'bob',
            'password' => 'N3w-Password',
        ], false));

        $this->assertSame('POST /api/hosting-accounts/7/change-password', $this->calls()[1]);
        $this->assertSame(['password' => 'N3w-Password'], $this->requestPayload(1));
        $this->assertSame('Password changed', $result->getMessage());
    }

    public function testChangePasswordFailure(): void
    {
        $this->queueLookup($this->account());
        $this->queue(422, ['status' => 'error', 'message' => 'The password is too weak.']);

        $error = $this->catchProvisionError(function () {
            $this->makeProvider()->changePassword(ChangePasswordParams::create([
                'username' => 'bob',
                'password' => 'weak',
            ], false));
        });

        $this->assertSame('Failed to change password: The password is too weak.', $error->getMessage());
    }

    // changePackage

    public function testChangePackage(): void
    {
        $this->queueLookup($this->account());
        $this->queue(200, $this->account(['hosting_plan_id' => 4]));
        $this->queue(200, ['id' => 4, 'name' => 'Business']);

        $result = $this->makeProvider()->changePackage(ChangePackageParams::create([
            'username' => 'bob',
            'package_name' => 'Business',
        ], false));

        $this->assertSame([
            'GET /api/hosting-accounts?username=bob',
            'PUT /api/hosting-accounts/7',
            'GET /api/hosting-plans/4',
        ], $this->calls());
        $this->assertSame(['hosting_plan' => 'Business'], $this->requestPayload(1));
        $this->assertSame('Business', $this->resultValues($result)['package_name']);
    }

    // suspend / unSuspend

    public function testSuspend(): void
    {
        $this->queueLookup($this->account());
        $this->queue(200, ['message' => 'Suspended']);
        $this->queueLookup($this->account(['is_suspended' => true]));
        $this->queue(200, ['id' => 3, 'name' => 'Pro']);

        $result = $this->makeProvider()->suspend(SuspendParams::create(['username' => 'bob'], false));

        $this->assertSame('POST /api/hosting-accounts/7/suspend', $this->calls()[1]);
        $this->assertTrue($this->resultValues($result)['suspended']);
    }

    public function testSuspendAlreadySuspendedAccount(): void
    {
        $this->queueLookup($this->account(['is_suspended' => true]));
        $this->queueLookup($this->account(['is_suspended' => true]));
        $this->queue(200, ['id' => 3, 'name' => 'Pro']);

        $result = $this->makeProvider()->suspend(SuspendParams::create(['username' => 'bob'], false));

        $this->assertNotContains('POST /api/hosting-accounts/7/suspend', $this->calls());
        $this->assertTrue($this->resultValues($result)['suspended']);
    }

    public function testUnSuspend(): void
    {
        $this->queueLookup($this->account(['is_suspended' => true]));
        $this->queue(200, ['message' => 'Unsuspended']);
        $this->queueLookup($this->account());
        $this->queue(200, ['id' => 3, 'name' => 'Pro']);

        $result = $this->makeProvider()->unSuspend(AccountUsername::create(['username' => 'bob'], false));

        $this->assertSame('POST /api/hosting-accounts/7/unsuspend', $this->calls()[1]);
        $this->assertFalse($this->resultValues($result)['suspended']);
    }

    // terminate

    public function testTerminate(): void
    {
        $this->queueLookup($this->account());
        $this->queue(200, ['message' => 'Deleted']);

        $result = $this->makeProvider()->terminate(AccountUsername::create(['username' => 'bob'], false));

        $this->assertSame('DELETE /api/hosting-accounts/7', $this->calls()[1]);
        $this->assertSame('Account terminated', $result->getMessage());
    }

    public function testTerminateMissingAccountSucceeds(): void
    {
        $this->queueLookup();

        $result = $this->makeProvider()->terminate(AccountUsername::create(['username' => 'bob'], false));

        $this->assertCount(1, $this->history);
        $this->assertSame('Account already terminated', $result->getMessage());
    }

    // unsupported

    public function testUnsupportedFunctions(): void
    {
        $provider = $this->makeProvider();
        $calls = [
            fn () => $provider->changePrimaryDomain(ChangePrimaryDomainParams::create([
                'username' => 'bob',
                'domain' => 'example.org',
            ], false)),
            fn () => $provider->grantReseller(GrantResellerParams::create(['username' => 'bob'], false)),
            fn () => $provider->revokeReseller(AccountUsername::create(['username' => 'bob'], false)),
        ];

        foreach ($calls as $call) {
            $this->assertSame('Operation not supported', $this->catchProvisionError($call)->getMessage());
        }

        $this->assertSame([], $this->history);
    }
}
