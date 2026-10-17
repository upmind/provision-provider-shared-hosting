<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\Koapanel\Data;

use Upmind\ProvisionBase\Provider\DataSet\DataSet;
use Upmind\ProvisionBase\Provider\DataSet\Rules;

/**
 * Koapanel API credentials: the panel's address and a personal API key of a
 * panel administrator or reseller (Koapanel › API keys, "kpk_…").
 *
 * @property-read string $hostname Panel hostname or IP address
 * @property-read int|null $port Panel port (default 8443)
 * @property-read string $api_key Personal API key of an administrator or reseller
 * @property-read bool|null $verify_tls Verify the TLS certificate (default true)
 * @property-read bool|null $create_site Also create the site of the order's domain (default true)
 * @property-read string|null $php_version PHP version of new sites, e.g. 8.3 (default: the panel's)
 */
class Configuration extends DataSet
{
    public static function rules(): Rules
    {
        return new Rules([
            'hostname' => ['required', 'string', 'regex:/^[A-Za-z0-9.:\[\]-]{1,253}$/'],
            'port' => ['nullable', 'integer', 'min:1', 'max:65535'],
            'api_key' => ['required', 'string'],
            'verify_tls' => ['nullable', 'boolean'],
            'create_site' => ['nullable', 'boolean'],
            'php_version' => ['nullable', 'string', 'regex:/^\d\.\d$/'],
        ]);
    }
}
