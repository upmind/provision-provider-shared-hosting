<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\Tests\Unit\Enhance;

use Carbon\Carbon;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Illuminate\Container\Container;
use Illuminate\Support\Facades\Facade;
use Illuminate\Translation\ArrayLoader;
use Illuminate\Translation\Translator;
use Illuminate\Validation\Factory as ValidatorFactory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Upmind\ProvisionBase\Provider\DataSet\Validator as DataSetValidator;
use Upmind\ProvisionProviders\SharedHosting\Data\GetLoginUrlParams;
use Upmind\ProvisionProviders\SharedHosting\Enhance\Api;
use Upmind\ProvisionProviders\SharedHosting\Enhance\Data\Configuration;
use Upmind\ProvisionProviders\SharedHosting\Enhance\Provider;

/**
 * getLoginUrl() with `type` = `token`, against mocked Enhance API responses.
 *
 * Params and configuration are built with validation disabled, and results are
 * validated by a validator factory backed by a minimal container, so the tests
 * don't need a Laravel application.
 */
class LoginTokenTest extends TestCase
{
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

        $container = new Container();
        $container->instance('validator', $factory);
        Facade::setFacadeApplication($container);

        $this->history = [];
    }

    protected function tearDown(): void
    {
        Carbon::setTestNow();
        Facade::clearResolvedInstances();
        Facade::setFacadeApplication(null);

        parent::tearDown();
    }

    /**
     * @param Response[] $responses
     */
    protected function makeProvider(array $responses): Provider
    {
        $configuration = Configuration::create([
            'hostname' => 'cp.example.com',
            'org_id' => 'reseller-org-id',
            'access_token' => 'access-token',
        ], false);

        $stack = HandlerStack::create(new MockHandler($responses));
        $stack->push(Middleware::history($this->history));

        $api = new Api($configuration);
        $api->setClient(new Client(['handler' => $stack]));

        return new class ($configuration, $api) extends Provider {
            public function __construct(Configuration $configuration, Api $api)
            {
                parent::__construct($configuration);

                $this->api = $api;
            }
        };
    }

    protected function requestAt(int $index): RequestInterface
    {
        return $this->history[$index]['request'];
    }

    public function testGetLoginUrlReturnsSessionToken(): void
    {
        Carbon::setTestNow(Carbon::parse('2026-01-01 12:00:00', 'UTC'));

        $provider = $this->makeProvider([
            new Response(200, ['Content-Type' => 'application/json'], json_encode([
                'items' => [
                    ['id' => 'owner-member-id', 'email' => 'owner@example.com', 'roles' => ['Owner']],
                ],
                'total' => 1,
            ])),
            new Response(201, ['Content-Type' => 'application/json'], json_encode('session-token')),
        ]);

        $result = $provider->getLoginUrl(GetLoginUrlParams::create([
            'customer_id' => 'customer-org-id',
            'username' => 'owner@example.com',
            'user_ip' => '192.0.2.1',
            'type' => 'token',
        ], false));

        $this->assertSame('token', $result->type);
        $this->assertSame('session-token', $result->token);
        $this->assertNull($result->login_url);
        $this->assertSame('2026-01-01 12:01:00', $result->expires);

        $this->assertCount(2, $this->history);
        $this->assertSame('GET', $this->requestAt(0)->getMethod());
        $this->assertSame('/api/orgs/customer-org-id/members', $this->requestAt(0)->getUri()->getPath());
        $this->assertSame('POST', $this->requestAt(1)->getMethod());
        $this->assertSame(
            '/api/orgs/customer-org-id/members/owner-member-id/session',
            $this->requestAt(1)->getUri()->getPath()
        );
    }
}
