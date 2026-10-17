<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\Koapanel;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\TransferException;
use GuzzleHttp\HandlerStack;
use Upmind\ProvisionProviders\SharedHosting\Koapanel\Data\Configuration;

/**
 * Minimal client of the Koapanel REST API v1 (every panel serves its
 * OpenAPI description at /api/v1/openapi.json). Errors are
 * {"error":{"code","message","field?","requestId"}}; POST requests accept
 * an Idempotency-Key.
 */
class Api
{
    protected Client $client;

    public function __construct(Configuration $configuration, ?HandlerStack $handler = null)
    {
        $host = trim($configuration->hostname);
        if (str_contains($host, ':') && !str_starts_with($host, '[')) {
            $host = '[' . $host . ']'; // IPv6
        }

        $this->client = new Client([
            'base_uri' => sprintf('https://%s:%d/api/v1/', $host, $configuration->port ?: 8443),
            'headers' => [
                'Authorization' => 'Bearer ' . $configuration->api_key,
                'Accept' => 'application/json',
                'User-Agent' => 'upmind-provision-koapanel/1.0',
            ],
            'connect_timeout' => 10,
            'timeout' => 60,
            'http_errors' => false,
            'allow_redirects' => false,
            'verify' => $configuration->verify_tls ?? true,
            'handler' => $handler,
        ]);
    }

    /**
     * @param array<string,mixed>|null $body
     * @param array<string,scalar> $query
     *
     * @return array<string,mixed>
     *
     * @throws ApiError
     */
    public function request(
        string $method,
        string $path,
        ?array $body = null,
        array $query = [],
        ?string $idempotencyKey = null
    ): array {
        $options = [];
        if ($body !== null) {
            $options['json'] = $body === [] ? new \stdClass() : $body;
        }
        if ($query) {
            $options['query'] = $query;
        }
        if ($idempotencyKey !== null) {
            $options['headers'] = ['Idempotency-Key' => $idempotencyKey];
        }

        try {
            $response = $this->client->request($method, ltrim($path, '/'), $options);
        } catch (TransferException $e) {
            throw new ApiError(0, 'network', 'The server could not be reached', null, $e);
        }

        $raw = (string) $response->getBody();
        $data = $raw === '' ? [] : json_decode($raw, true);
        if (!is_array($data)) {
            $data = [];
        }
        $status = $response->getStatusCode();
        if ($status >= 400) {
            $err = is_array($data['error'] ?? null) ? $data['error'] : [];

            throw new ApiError(
                $status,
                (string) ($err['code'] ?? 'http_' . $status),
                (string) ($err['message'] ?? 'HTTP ' . $status),
                isset($err['field']) ? (string) $err['field'] : null
            );
        }

        return $data;
    }

    public static function seg(string $value): string
    {
        return rawurlencode($value);
    }
}
