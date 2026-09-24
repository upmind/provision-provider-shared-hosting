<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\CyberPanel;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Exception\TransferException;
use JsonException;
use Upmind\ProvisionBase\Exception\ProvisionFunctionError;
use Upmind\ProvisionProviders\SharedHosting\CyberPanel\Data\Configuration;
use Upmind\ProvisionProviders\SharedHosting\Data\CreateParams;

/**
 * Thin wrapper around the CyberPanel cloud API.
 *
 * The public API is deliberately small - it only exposes the handful of
 * endpoints documented at https://cyberpanel.docs.apiary.io and defined in
 * cyberpanel/api/urls.py. Notably there is no endpoint to read a website's
 * package, suspension state or resource usage, which constrains getInfo()
 * and getUsage() in the Provider.
 */
class Api
{
    private Client $client;
    private Configuration $configuration;

    public function __construct(Client $client, Configuration $configuration)
    {
        $this->client = $client;
        $this->configuration = $configuration;
    }

    /**
     * Perform an authenticated POST to the given API function and return the
     * decoded JSON response.
     *
     * @param array<string, mixed> $params
     *
     * @return array<string, mixed>
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function makeRequest(string $function, array $params = []): array
    {
        $params = array_merge($params, [
            'adminUser' => $this->configuration->getUsername(),
            'adminPass' => $this->configuration->getPassword(),
        ]);

        try {
            $response = $this->client->request('POST', "api/{$function}", [
                'json' => $params,
            ]);
        } catch (ConnectException $e) {
            throw ProvisionFunctionError::create('Unable to connect to the hosting server', $e)
                ->withData(['function' => $function]);
        } catch (RequestException $e) {
            $response = $e->getResponse();

            throw ProvisionFunctionError::create('The hosting server returned an error response', $e)
                ->withData([
                    'function' => $function,
                    'status_code' => $response ? $response->getStatusCode() : null,
                ]);
        } catch (TransferException $e) {
            throw ProvisionFunctionError::create('Failed to communicate with the hosting server', $e)
                ->withData(['function' => $function]);
        }

        return $this->parseResponse((string)$response->getBody());
    }

    /**
     * Decode a JSON API response body.
     *
     * @return array<string, mixed>
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    protected function parseResponse(string $body): array
    {
        try {
            $data = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw ProvisionFunctionError::create('Received an unexpected response from the hosting server', $e)
                ->withData(['response_body' => $body]);
        }

        if (!is_array($data)) {
            throw ProvisionFunctionError::create('Received an unexpected response from the hosting server')
                ->withData(['response_body' => $body]);
        }

        return $data;
    }

    /**
     * Assert the API responded with the expected success flag, otherwise throw
     * a ProvisionFunctionError carrying the panel's own (unsafe) message as debug.
     *
     * @param array<string, mixed> $response
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    protected function assertSuccess(array $response, string $statusKey, string $errorMessage): void
    {
        if (isset($response[$statusKey]) && (int)$response[$statusKey] === 1) {
            return;
        }

        throw ProvisionFunctionError::create($errorMessage)
            ->withData([
                'error' => $response['error_message'] ?? null,
            ]);
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function createAccount(CreateParams $params, string $username, string $password): void
    {
        $response = $this->makeRequest('createWebsite', [
            'domainName' => $params->domain,
            'ownerEmail' => $params->email,
            'packageName' => $params->package_name,
            'websiteOwner' => $username,
            'ownerPassword' => $password,
        ]);

        $this->assertSuccess($response, 'createWebSiteStatus', 'Failed to create hosting account');
    }

    /**
     * Confirm the given account exists.
     *
     * The API's getUserInfo returns only the user's name/email/status - no
     * package, domain or suspension data - so this is used purely as an
     * existence check.
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function assertAccountExists(string $username): void
    {
        $response = $this->makeRequest('getUserInfo', [
            'username' => $username,
        ]);

        $this->assertSuccess($response, 'status', 'Account not found');
    }

    /**
     * Fetch the list of available package names.
     *
     * @return string[]
     *
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function listPackageNames(): array
    {
        $response = $this->makeRequest('listPackage');

        // A successful response is a bare JSON array of package name strings.
        // Only failure responses are objects, carrying a status flag/message.
        if (isset($response['status']) && (int)$response['status'] !== 1) {
            throw ProvisionFunctionError::create('Failed to retrieve the package list')
                ->withData(['error' => $response['error_message'] ?? null]);
        }

        // Bare array (self-hosted), or wrapped under 'listPackages' on some versions.
        $packages = $response['listPackages'] ?? $response;

        // Some versions return the list as a JSON-encoded string.
        if (is_string($packages)) {
            $decoded = json_decode($packages, true);
            $packages = is_array($decoded) ? $decoded : [];
        }

        if (!is_array($packages)) {
            return [];
        }

        return array_values(array_filter(array_map(
            function ($package) {
                return is_string($package) ? $package : ($package['packageName'] ?? null);
            },
            $packages
        )));
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function assertPackageExists(string $packageName): void
    {
        if (!in_array($packageName, $this->listPackageNames(), true)) {
            throw ProvisionFunctionError::create('The requested package does not exist on the server')
                ->withData(['package' => $packageName]);
        }
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function updatePassword(string $username, string $password): void
    {
        $response = $this->makeRequest('changeUserPassAPI', [
            'websiteOwner' => $username,
            'ownerPassword' => $password,
        ]);

        $this->assertSuccess($response, 'changeStatus', 'Failed to change account password');
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function updatePackage(string $domain, string $packageName): void
    {
        $response = $this->makeRequest('changePackageAPI', [
            'websiteName' => $domain,
            'packageName' => $packageName,
        ]);

        $this->assertSuccess($response, 'changePackage', 'Failed to change account package');
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function setWebsiteStatus(string $domain, string $state): void
    {
        $response = $this->makeRequest('submitWebsiteStatus', [
            'websiteName' => $domain,
            'state' => $state,
        ]);

        $this->assertSuccess($response, 'websiteStatus', 'Failed to update account status');
    }

    /**
     * @throws \Upmind\ProvisionBase\Exception\ProvisionFunctionError
     */
    public function deleteAccount(string $domain): void
    {
        $response = $this->makeRequest('deleteWebsite', [
            'domainName' => $domain,
        ]);

        $this->assertSuccess($response, 'websiteDeleteStatus', 'Failed to delete hosting account');
    }
}
