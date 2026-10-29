<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\Tests\Unit\Data;

use Illuminate\Support\Facades\Validator;
use Illuminate\Translation\ArrayLoader;
use Illuminate\Translation\Translator;
use Illuminate\Validation\Factory as ValidatorFactory;
use PHPUnit\Framework\TestCase;
use Upmind\ProvisionBase\Provider\DataSet\RuleParser;
use Upmind\ProvisionBase\Provider\DataSet\Validator as DataSetValidator;
use Upmind\ProvisionProviders\SharedHosting\Data\GetLoginUrlParams;
use Upmind\ProvisionProviders\SharedHosting\Data\LoginUrl;

/**
 * Validation of the optional login `type` param and the url/token login result.
 *
 * Data sets are validated by a standalone validator factory, so the tests
 * don't need a Laravel application.
 */
class LoginTypeTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        $factory = new ValidatorFactory(new Translator(new ArrayLoader(), 'en'));
        $factory->resolver(function ($translator, $data, $rules, $messages, $customAttributes) use ($factory) {
            return new DataSetValidator($factory, $translator, $data, $rules, $messages, $customAttributes);
        });

        Validator::swap($factory);
        RuleParser::setValidator($factory->make([], []));
    }

    /**
     * @param array<string, mixed> $values
     */
    protected function makeParams(array $values = []): GetLoginUrlParams
    {
        return new GetLoginUrlParams(array_merge([
            'username' => 'bob',
            'user_ip' => '192.0.2.1',
        ], $values));
    }

    public function testParamsTypeIsOptional(): void
    {
        $params = $this->makeParams();

        $this->assertSame([], $params->errors());
        $this->assertNull($params->type);
        $this->assertFalse($params->wantsToken());
    }

    public function testParamsAcceptUrlAndTokenTypes(): void
    {
        $this->assertFalse($this->makeParams(['type' => 'url'])->wantsToken());
        $this->assertTrue($this->makeParams(['type' => 'token'])->wantsToken());
    }

    public function testParamsRejectUnknownType(): void
    {
        $this->assertArrayHasKey('type', $this->makeParams(['type' => 'cookie'])->errors());
    }

    public function testLoginUrlResultDefaultsToUrlType(): void
    {
        $result = LoginUrl::create()->setLoginUrl('https://panel.example.com/sso?otp=abc');

        $this->assertSame([], $result->errors());
        $this->assertSame('url', $result->type);
        $this->assertSame('https://panel.example.com/sso?otp=abc', $result->login_url);
        $this->assertNull($result->token);
    }

    public function testTokenResult(): void
    {
        $result = LoginUrl::create()->setToken('abc123');

        $this->assertSame([], $result->errors());
        $this->assertSame('token', $result->type);
        $this->assertSame('abc123', $result->token);
        $this->assertNull($result->login_url);
    }

    public function testResultRequiresUrlOrToken(): void
    {
        $errors = LoginUrl::create()->errors();

        $this->assertArrayHasKey('login_url', $errors);
        $this->assertArrayHasKey('token', $errors);
    }

    public function testResultRejectsUnknownType(): void
    {
        $result = LoginUrl::create()->setLoginUrl('https://panel.example.com')->setType('cookie');

        $this->assertArrayHasKey('type', $result->errors());
    }
}
