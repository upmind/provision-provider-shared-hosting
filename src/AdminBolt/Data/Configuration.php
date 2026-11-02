<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\AdminBolt\Data;

use Upmind\ProvisionBase\Provider\DataSet\DataSet;
use Upmind\ProvisionBase\Provider\DataSet\Rules;

/**
 * AdminBolt API credentials.
 *
 * @property-read string $hostname Server hostname of the AdminBolt panel
 * @property-read int|null $port Panel port (default 8443)
 * @property-read string $api_key API key, from Security > API Keys in the admin or reseller panel
 * @property-read string $api_secret API secret
 * @property-read bool|null $use_reseller_api The key pair belongs to a reseller; accounts are created under it
 * @property-read bool|null $ignore_ssl_errors Do not verify the panel's TLS certificate
 */
class Configuration extends DataSet
{
    public static function rules(): Rules
    {
        return new Rules([
            'hostname' => ['required', 'domain_name'],
            'port' => ['nullable', 'integer', 'min:1', 'max:65535'],
            'api_key' => ['required', 'string'],
            'api_secret' => ['required', 'string'],
            'use_reseller_api' => ['nullable', 'boolean'],
            'ignore_ssl_errors' => ['nullable', 'boolean'],
        ]);
    }
}
