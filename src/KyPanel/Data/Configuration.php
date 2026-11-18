<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\KyPanel\Data;

use Upmind\ProvisionBase\Provider\DataSet\DataSet;
use Upmind\ProvisionBase\Provider\DataSet\Rules;

/**
 * KyPanel API credentials.
 *
 * @property-read string $hostname KyPanel server hostname
 * @property-read int|null $port API port (default 7711)
 * @property-read string $api_token Admin API token with "accounts" (read and change) and "packages" (read)
 * @property-read bool|null $ssl_verify Verify the server certificate (default true)
 */
class Configuration extends DataSet
{
    public static function rules(): Rules
    {
        return new Rules([
            'hostname' => ['required', 'string', 'domain_name'],
            'port' => ['nullable', 'integer'],
            'api_token' => ['required', 'string'],
            'ssl_verify' => ['nullable', 'boolean'],
        ]);
    }
}
