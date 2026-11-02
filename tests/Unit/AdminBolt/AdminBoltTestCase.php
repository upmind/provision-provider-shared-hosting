<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\Tests\Unit\AdminBolt;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Illuminate\Support\Facades\Validator;
use Illuminate\Translation\ArrayLoader;
use Illuminate\Translation\Translator;
use Illuminate\Validation\Factory as ValidatorFactory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Upmind\ProvisionBase\Exception\ProvisionFunctionError;
use Upmind\ProvisionBase\Provider\DataSet\DataSet;
use Upmind\ProvisionBase\Provider\DataSet\RuleParser;
use Upmind\ProvisionBase\Provider\DataSet\Validator as DataSetValidator;
use Upmind\ProvisionProviders\SharedHosting\AdminBolt\Data\Configuration;

/**
 * Shared helpers for AdminBolt tests: a Guzzle client backed by a queue of
 * mocked responses, plus a record of every request sent.
 *
 * Data sets are validated by a standalone validator factory, so the tests
 * don't need a Laravel application.
 */
abstract class AdminBoltTestCase extends TestCase
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

        $factory = new ValidatorFactory(new Translator(new ArrayLoader(), 'en'));
        $factory->resolver(function ($translator, $data, $rules, $messages, $customAttributes) use ($factory) {
            return new DataSetValidator($factory, $translator, $data, $rules, $messages, $customAttributes);
        });

        Validator::swap($factory);
        RuleParser::setValidator($factory->make([], []));

        $this->mockHandler = new MockHandler();
        $this->history = [];
    }

    /**
     * @param array<string, mixed> $overrides
     */
    protected function makeConfiguration(array $overrides = []): Configuration
    {
        return Configuration::create(array_merge([
            'hostname' => 'panel.example.com',
            'api_key' => 'key',
            'api_secret' => 'secret',
        ], $overrides), false);
    }

    protected function makeProvider(?Configuration $configuration = null): TestableProvider
    {
        $stack = HandlerStack::create($this->mockHandler);
        $stack->push(Middleware::history($this->history));

        return new TestableProvider(
            $configuration ?: $this->makeConfiguration(),
            new Client(['base_uri' => 'https://panel.example.com:8443/api/', 'handler' => $stack])
        );
    }

    /**
     * Queue JSON responses.
     *
     * @param mixed $body
     */
    protected function queue(int $status, $body): void
    {
        $this->mockHandler->append(new Response(
            $status,
            ['Content-Type' => 'application/json'],
            is_string($body) ? $body : json_encode($body)
        ));
    }

    /**
     * Queue the account list returned by a username lookup.
     *
     * @param array<string, mixed> ...$accounts
     */
    protected function queueLookup(array ...$accounts): void
    {
        $this->queue(200, $accounts);
    }

    /**
     * @return array<string, mixed>
     */
    protected function account(array $overrides = []): array
    {
        return array_merge([
            'id' => 7,
            'username' => 'bob',
            'domain' => 'example.com',
            'hosting_plan_id' => 3,
            'is_suspended' => false,
            'sso_token' => 'should-not-leak',
        ], $overrides);
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
        return json_decode((string) $this->requestAt($index)->getBody(), true);
    }

    /**
     * @return string[] "METHOD path?query" of every request, in order
     */
    protected function calls(): array
    {
        return array_map(function (array $transaction) {
            $uri = $transaction['request']->getUri();
            $query = $uri->getQuery();

            return $transaction['request']->getMethod() . ' ' . $uri->getPath() . ($query !== '' ? '?' . $query : '');
        }, $this->history);
    }

    /**
     * @return array<string, mixed>
     */
    protected function resultValues(DataSet $result): array
    {
        $result->autoValidation(false);

        return $result->toArray();
    }

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
