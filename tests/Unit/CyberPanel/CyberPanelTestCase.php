<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\Tests\Unit\CyberPanel;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Illuminate\Translation\ArrayLoader;
use Illuminate\Translation\Translator;
use Illuminate\Validation\Factory as ValidatorFactory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Upmind\ProvisionBase\Exception\ProvisionFunctionError;
use Upmind\ProvisionBase\Provider\DataSet\DataSet;
use Upmind\ProvisionBase\Provider\DataSet\RuleParser;
use Upmind\ProvisionProviders\SharedHosting\CyberPanel\Api;
use Upmind\ProvisionProviders\SharedHosting\CyberPanel\Data\Configuration;

/**
 * Shared helpers for CyberPanel tests: a Guzzle client backed by a queue of
 * mocked responses, plus a record of every request sent.
 *
 * Data sets are built with validation disabled, and rule parsing is given a
 * standalone validator, so the tests don't need a Laravel application.
 */
abstract class CyberPanelTestCase extends TestCase
{
    /**
     * @var MockHandler
     */
    protected $mockHandler;

    /**
     * @var array<int, array<string, mixed>>
     */
    protected $history = [];

    protected function setUp(): void
    {
        parent::setUp();

        $validatorFactory = new ValidatorFactory(new Translator(new ArrayLoader(), 'en'));
        RuleParser::setValidator($validatorFactory->make([], []));

        $this->mockHandler = new MockHandler();
        $this->history = [];
    }

    /**
     * @param array<string, mixed> $overrides
     */
    protected function makeConfiguration(array $overrides = []): Configuration
    {
        return Configuration::create(array_merge([
            'hostname' => 'cp.example.com',
            'port' => 8090,
            'username' => 'admin',
            'password' => 's3cret',
            'ssl_verify' => false,
        ], $overrides), false);
    }

    protected function makeClient(string $baseUri = 'https://cp.example.com:8090/'): Client
    {
        $stack = HandlerStack::create($this->mockHandler);
        $stack->push(Middleware::history($this->history));

        return new Client([
            'base_uri' => $baseUri,
            'handler' => $stack,
        ]);
    }

    protected function makeApi(?Configuration $configuration = null): Api
    {
        return new Api($this->makeClient(), $configuration ?: $this->makeConfiguration());
    }

    /**
     * Queue JSON responses (arrays are encoded, strings are sent verbatim).
     *
     * @param mixed ...$bodies
     */
    protected function queueJson(...$bodies): void
    {
        foreach ($bodies as $body) {
            $this->mockHandler->append(new Response(
                200,
                ['Content-Type' => 'application/json'],
                is_string($body) ? $body : json_encode($body)
            ));
        }
    }

    protected function requestAt(int $index): RequestInterface
    {
        $this->assertArrayHasKey($index, $this->history, sprintf('No request #%d was sent', $index));

        return $this->history[$index]['request'];
    }

    /**
     * @return array<string, mixed>
     */
    protected function requestPayload(int $index): array
    {
        return json_decode((string)$this->requestAt($index)->getBody(), true);
    }

    /**
     * @return string[] API function names in the order they were called
     */
    protected function calledFunctions(): array
    {
        return array_map(function (array $transaction) {
            return preg_replace('#^/api/#', '', $transaction['request']->getUri()->getPath());
        }, $this->history);
    }

    /**
     * Read a result data set's values without triggering validation.
     *
     * @return array<string, mixed>
     */
    protected function resultValues(DataSet $result): array
    {
        $result->autoValidation(false);

        return $result->toArray();
    }

    /**
     * Run the callback and return the ProvisionFunctionError it throws.
     */
    protected function catchProvisionError(callable $callback): ProvisionFunctionError
    {
        try {
            $callback();
        } catch (ProvisionFunctionError $e) {
            return $e;
        }

        $this->fail('Expected ' . ProvisionFunctionError::class . ' to be thrown');
    }
}
