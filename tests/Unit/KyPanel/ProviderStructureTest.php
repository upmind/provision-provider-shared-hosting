<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\Tests\Unit\KyPanel;

use PHPUnit\Framework\TestCase;
use ReflectionClass;
use ReflectionMethod;
use Upmind\ProvisionBase\Provider\Contract\LogsDebugData;
use Upmind\ProvisionBase\Provider\Contract\ProviderInterface;
use Upmind\ProvisionProviders\SharedHosting\Category;
use Upmind\ProvisionProviders\SharedHosting\KyPanel\Data\Configuration;
use Upmind\ProvisionProviders\SharedHosting\KyPanel\Provider as KyPanelProvider;

/**
 * Basic unit tests for KyPanel Provider.
 */
class ProviderStructureTest extends TestCase
{
    public function testProviderClassExists(): void
    {
        $this->assertTrue(class_exists(KyPanelProvider::class));
    }

    public function testProviderImplementsLogsDebugData(): void
    {
        $this->assertContains(
            LogsDebugData::class,
            class_implements(KyPanelProvider::class)
        );
    }

    /**
     * @dataProvider requiredMethodProvider
     */
    public function testProviderImplementsRequiredMethod(string $method): void
    {
        $reflection = new ReflectionClass(KyPanelProvider::class);

        $this->assertTrue($reflection->hasMethod($method), sprintf('Missing method %s()', $method));

        $reflectionMethod = $reflection->getMethod($method);
        $this->assertTrue($reflectionMethod->isPublic(), sprintf('%s() must be public', $method));
        $this->assertFalse($reflectionMethod->isAbstract(), sprintf('%s() must be implemented', $method));
        $this->assertSame(
            KyPanelProvider::class,
            $reflectionMethod->getDeclaringClass()->getName(),
            sprintf('%s() must be declared by the KyPanel provider', $method)
        );
    }

    /**
     * @return array<string, array<int, string>>
     */
    public static function requiredMethodProvider(): array
    {
        $methods = [
            'aboutProvider',
            'create',
            'getInfo',
            'getUsage',
            'getLoginUrl',
            'changePassword',
            'changePackage',
            'changePrimaryDomain',
            'suspend',
            'unSuspend',
            'terminate',
            'grantReseller',
            'revokeReseller',
        ];

        return array_combine($methods, array_map(static function ($method) {
            return [$method];
        }, $methods));
    }

    public function testProviderImplementsEveryCategoryFunction(): void
    {
        $category = new ReflectionClass(Category::class);
        $abstractMethods = array_map(static function (ReflectionMethod $method) {
            return $method->getName();
        }, $category->getMethods(ReflectionMethod::IS_ABSTRACT));

        $this->assertNotEmpty($abstractMethods);
        $this->assertEmpty(
            array_diff($abstractMethods, array_keys(self::requiredMethodProvider())),
            'requiredMethodProvider() is missing category functions'
        );
        $this->assertFalse((new ReflectionClass(KyPanelProvider::class))->isAbstract());
    }

    public function testProviderExtendsCategory(): void
    {
        $this->assertTrue(
            is_subclass_of(
                KyPanelProvider::class,
                Category::class
            )
        );
    }

    public function testProviderImplementsProviderInterface(): void
    {
        $this->assertContains(
            ProviderInterface::class,
            class_implements(KyPanelProvider::class)
        );
    }

    public function testConfigurationClassExists(): void
    {
        $this->assertTrue(
            class_exists(
                Configuration::class
            )
        );
    }
}
