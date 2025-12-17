<?php

declare(strict_types=1);

namespace Tests\CyberPanel;

use PHPUnit\Framework\TestCase;
use Upmind\ProvisionProviders\SharedHosting\CyberPanel\Provider as CyberPanelProvider;

/**
 * Basic unit tests for CyberPanel Provider.
 */
class ProviderTest extends TestCase
{
    public function testProviderClassExists(): void
    {
        $this->assertTrue(class_exists(CyberPanelProvider::class));
    }

    public function testProviderImplementsLogsDebugData(): void
    {
        $this->assertTrue(
            in_array(
                \Upmind\ProvisionBase\Provider\Contract\LogsDebugData::class,
                class_implements(CyberPanelProvider::class)
            )
        );
    }

    public function testProviderHasRequiredMethods(): void
    {
        $reflection = new \ReflectionClass(CyberPanelProvider::class);
        
        $this->assertTrue($reflection->hasMethod('create'));
        $this->assertTrue($reflection->hasMethod('getInfo'));
        $this->assertTrue($reflection->hasMethod('changePassword'));
        $this->assertTrue($reflection->hasMethod('changePackage'));
        $this->assertTrue($reflection->hasMethod('getLoginUrl'));
    }

    public function testProviderExtendsCategory(): void
    {
        $this->assertTrue(
            is_subclass_of(
                CyberPanelProvider::class,
                \Upmind\ProvisionProviders\SharedHosting\Category::class
            )
        );
    }

    public function testProviderImplementsProviderInterface(): void
    {
        $this->assertTrue(
            in_array(
                \Upmind\ProvisionBase\Provider\Contract\ProviderInterface::class,
                class_implements(CyberPanelProvider::class)
            )
        );
    }

    public function testConfigurationClassExists(): void
    {
        $this->assertTrue(
            class_exists(
                \Upmind\ProvisionProviders\SharedHosting\CyberPanel\Data\Configuration::class
            )
        );
    }
}