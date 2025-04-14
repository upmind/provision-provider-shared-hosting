<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\SPanel\Data;

use Upmind\ProvisionBase\Provider\DataSet\DataSet;
use Upmind\ProvisionBase\Provider\DataSet\Rules;

/**
 * SPanel API credentials.
 * @property-read string $hostname SPanel server hostname
 * @property-read string $api_token SPanel API token
 * @property-read string $username SPanel username
 */
class Configuration extends DataSet
{
    public static function rules(): Rules
    {
        return new Rules([
            'hostname' => ['required', 'domain_name'],
            'username' => ['required', 'string'],
            'api_token' => ['required', 'string']
        ]);
    }
}
