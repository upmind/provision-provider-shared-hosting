<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\Tests\Unit\CyberPanel;

use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\TransferException;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Upmind\ProvisionProviders\SharedHosting\Data\CreateParams;

class ApiTest extends CyberPanelTestCase
{
    public function testMakeRequestPostsJsonWithAdminCredentials(): void
    {
        $this->queueJson(['status' => 1]);

        $response = $this->makeApi()->makeRequest('getUserInfo', ['username' => 'bob']);

        $this->assertSame(['status' => 1], $response);

        $request = $this->requestAt(0);
        $this->assertSame('POST', $request->getMethod());
        $this->assertSame('https://cp.example.com:8090/api/getUserInfo', (string)$request->getUri());
        $this->assertSame([
            'username' => 'bob',
            'adminUser' => 'admin',
            'adminPass' => 's3cret',
        ], $this->requestPayload(0));
    }

    public function testMakeRequestAdminCredentialsCannotBeOverriddenByParams(): void
    {
        $this->queueJson(['status' => 1]);

        $this->makeApi()->makeRequest('getUserInfo', ['adminUser' => 'hacker', 'adminPass' => 'nope']);

        $payload = $this->requestPayload(0);
        $this->assertSame('admin', $payload['adminUser']);
        $this->assertSame('s3cret', $payload['adminPass']);
    }

    public function testMakeRequestWrapsConnectException(): void
    {
        $this->mockHandler->append(
            new ConnectException('Connection refused', new Request('POST', 'api/getUserInfo'))
        );

        $error = $this->catchProvisionError(function () {
            $this->makeApi()->makeRequest('getUserInfo');
        });

        $this->assertSame('Unable to connect to the hosting server', $error->getMessage());
        $this->assertSame(['function' => 'getUserInfo'], $error->getData());
        $this->assertInstanceOf(ConnectException::class, $error->getPrevious());
    }

    public function testMakeRequestWrapsHttpErrorResponse(): void
    {
        $this->mockHandler->append(new Response(500, [], 'Internal Server Error'));

        $error = $this->catchProvisionError(function () {
            $this->makeApi()->makeRequest('createWebsite');
        });

        $this->assertSame('The hosting server returned an error response', $error->getMessage());
        $this->assertSame(['function' => 'createWebsite', 'status_code' => 500], $error->getData());
    }

    public function testMakeRequestWrapsGenericTransferException(): void
    {
        $this->mockHandler->append(new TransferException('Something broke'));

        $error = $this->catchProvisionError(function () {
            $this->makeApi()->makeRequest('listPackage');
        });

        $this->assertSame('Failed to communicate with the hosting server', $error->getMessage());
        $this->assertSame(['function' => 'listPackage'], $error->getData());
    }

    /**
     * @dataProvider invalidResponseBodyProvider
     */
    public function testMakeRequestRejectsInvalidResponseBody(string $body): void
    {
        $this->queueJson($body);

        $error = $this->catchProvisionError(function () {
            $this->makeApi()->makeRequest('getUserInfo');
        });

        $this->assertSame('Received an unexpected response from the hosting server', $error->getMessage());
        $this->assertSame(['response_body' => $body], $error->getData());
    }

    /**
     * @return array<string, array<int, string>>
     */
    public static function invalidResponseBodyProvider(): array
    {
        return [
            'html' => ['<html>Login</html>'],
            'empty' => [''],
            'truncated json' => ['{"status": 1'],
            'json string' => ['"ok"'],
            'json number' => ['1'],
            'json null' => ['null'],
        ];
    }

    public function testCreateAccountSendsExpectedPayload(): void
    {
        $this->queueJson(['createWebSiteStatus' => 1]);

        $params = CreateParams::create([
            'domain' => 'example.com',
            'email' => 'owner@example.com',
            'package_name' => 'Default',
        ], false);

        $this->makeApi()->createAccount($params, 'exampl12', 'P4ssword!');

        $this->assertSame(['createWebsite'], $this->calledFunctions());
        $this->assertSame([
            'domainName' => 'example.com',
            'ownerEmail' => 'owner@example.com',
            'packageName' => 'Default',
            'websiteOwner' => 'exampl12',
            'ownerPassword' => 'P4ssword!',
            'adminUser' => 'admin',
            'adminPass' => 's3cret',
        ], $this->requestPayload(0));
    }

    public function testCreateAccountFailureCarriesPanelErrorMessage(): void
    {
        $this->queueJson(['createWebSiteStatus' => 0, 'error_message' => 'Domain already exists']);

        $params = CreateParams::create([
            'domain' => 'example.com',
            'email' => 'owner@example.com',
            'package_name' => 'Default',
        ], false);

        $error = $this->catchProvisionError(function () use ($params) {
            $this->makeApi()->createAccount($params, 'exampl12', 'P4ssword!');
        });

        $this->assertSame('Failed to create hosting account', $error->getMessage());
        $this->assertSame(['error' => 'Domain already exists'], $error->getData());
    }

    public function testSuccessFlagAcceptsNumericString(): void
    {
        $this->queueJson(['status' => '1']);

        $this->makeApi()->assertAccountExists('bob');

        $this->assertSame(['getUserInfo'], $this->calledFunctions());
    }

    public function testMissingSuccessFlagIsTreatedAsFailure(): void
    {
        $this->queueJson(['something' => 'else']);

        $error = $this->catchProvisionError(function () {
            $this->makeApi()->assertAccountExists('bob');
        });

        $this->assertSame('Account not found', $error->getMessage());
        $this->assertSame(['error' => null], $error->getData());
    }

    public function testAssertAccountExistsSendsUsername(): void
    {
        $this->queueJson(['status' => 1]);

        $this->makeApi()->assertAccountExists('bob');

        $this->assertSame('bob', $this->requestPayload(0)['username']);
    }

    /**
     * @dataProvider packageListResponseProvider
     *
     * @param string $body
     * @param string[] $expected
     */
    public function testListPackageNamesHandlesResponseFormats(string $body, array $expected): void
    {
        $this->queueJson($body);

        $this->assertSame($expected, $this->makeApi()->listPackageNames());
        $this->assertSame(['listPackage'], $this->calledFunctions());
    }

    /**
     * @return array<string, array<int, mixed>>
     */
    public static function packageListResponseProvider(): array
    {
        return [
            'bare array of names' => [
                '["Default","Pro"]',
                ['Default', 'Pro'],
            ],
            'bare array of objects' => [
                '[{"packageName":"Default"},{"packageName":"Pro"}]',
                ['Default', 'Pro'],
            ],
            'wrapped array' => [
                '{"status":1,"listPackages":["Default","Pro"]}',
                ['Default', 'Pro'],
            ],
            'wrapped json-encoded string' => [
                json_encode(['status' => 1, 'listPackages' => json_encode([['packageName' => 'Default']])]),
                ['Default'],
            ],
            'wrapped undecodable string' => [
                '{"status":1,"listPackages":"not json"}',
                [],
            ],
            'wrapped scalar' => [
                '{"status":1,"listPackages":5}',
                [],
            ],
            'entries without names are dropped' => [
                '["Default",{"foo":"bar"},"",{"packageName":"Pro"}]',
                ['Default', 'Pro'],
            ],
            'empty list' => [
                '[]',
                [],
            ],
        ];
    }

    public function testListPackageNamesFailure(): void
    {
        $this->queueJson(['status' => 0, 'error_message' => 'Invalid credentials']);

        $error = $this->catchProvisionError(function () {
            $this->makeApi()->listPackageNames();
        });

        $this->assertSame('Failed to retrieve the package list', $error->getMessage());
        $this->assertSame(['error' => 'Invalid credentials'], $error->getData());
    }

    public function testAssertPackageExistsPasses(): void
    {
        $this->queueJson(['Default', 'Pro']);

        $this->makeApi()->assertPackageExists('Pro');

        $this->assertSame(['listPackage'], $this->calledFunctions());
    }

    public function testAssertPackageExistsIsCaseSensitive(): void
    {
        $this->queueJson(['Default', 'Pro']);

        $error = $this->catchProvisionError(function () {
            $this->makeApi()->assertPackageExists('pro');
        });

        $this->assertSame('The requested package does not exist on the server', $error->getMessage());
        $this->assertSame(['package' => 'pro'], $error->getData());
    }

    /**
     * @dataProvider simpleEndpointProvider
     *
     * @param string $method Api method name
     * @param array<int, string> $args
     * @param string $function Expected API function
     * @param array<string, string> $expectedParams
     * @param string $statusKey Success flag in the response
     * @param string $errorMessage Expected failure message
     */
    public function testSimpleEndpointSuccess(
        string $method,
        array $args,
        string $function,
        array $expectedParams,
        string $statusKey,
        string $errorMessage
    ): void {
        $this->queueJson([$statusKey => 1]);

        call_user_func_array([$this->makeApi(), $method], $args);

        $this->assertSame([$function], $this->calledFunctions());
        $this->assertSame(
            array_merge($expectedParams, ['adminUser' => 'admin', 'adminPass' => 's3cret']),
            $this->requestPayload(0)
        );
    }

    /**
     * @dataProvider simpleEndpointProvider
     *
     * @param string $method Api method name
     * @param array<int, string> $args
     * @param string $function Expected API function
     * @param array<string, string> $expectedParams
     * @param string $statusKey Success flag in the response
     * @param string $errorMessage Expected failure message
     */
    public function testSimpleEndpointFailure(
        string $method,
        array $args,
        string $function,
        array $expectedParams,
        string $statusKey,
        string $errorMessage
    ): void {
        $this->queueJson([$statusKey => 0, 'error_message' => 'Panel says no']);

        $api = $this->makeApi();
        $error = $this->catchProvisionError(function () use ($api, $method, $args) {
            call_user_func_array([$api, $method], $args);
        });

        $this->assertSame($errorMessage, $error->getMessage());
        $this->assertSame(['error' => 'Panel says no'], $error->getData());
    }

    /**
     * @return array<string, array<int, mixed>>
     */
    public static function simpleEndpointProvider(): array
    {
        return [
            'updatePassword' => [
                'updatePassword',
                ['bob', 'n3wPass'],
                'changeUserPassAPI',
                ['websiteOwner' => 'bob', 'ownerPassword' => 'n3wPass'],
                'changeStatus',
                'Failed to change account password',
            ],
            'updatePackage' => [
                'updatePackage',
                ['example.com', 'Pro'],
                'changePackageAPI',
                ['websiteName' => 'example.com', 'packageName' => 'Pro'],
                'changePackage',
                'Failed to change account package',
            ],
            'setWebsiteStatus suspend' => [
                'setWebsiteStatus',
                ['example.com', 'Suspend'],
                'submitWebsiteStatus',
                ['websiteName' => 'example.com', 'state' => 'Suspend'],
                'websiteStatus',
                'Failed to update account status',
            ],
            'setWebsiteStatus activate' => [
                'setWebsiteStatus',
                ['example.com', 'Activate'],
                'submitWebsiteStatus',
                ['websiteName' => 'example.com', 'state' => 'Activate'],
                'websiteStatus',
                'Failed to update account status',
            ],
            'deleteAccount' => [
                'deleteAccount',
                ['example.com'],
                'deleteWebsite',
                ['domainName' => 'example.com'],
                'websiteDeleteStatus',
                'Failed to delete hosting account',
            ],
        ];
    }
}
