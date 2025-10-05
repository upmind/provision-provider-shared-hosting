<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\CyberPanel\Data;

use Upmind\ProvisionBase\Provider\DataSet\DataSet;
use Upmind\ProvisionBase\Provider\DataSet\Rules;

/**
 * CyberPanel API credentials.
 *
 * @property-read string $hostname CyberPanel server hostname (e.g., https://89.117.57.23:8090)
 * @property-read string $username CyberPanel admin username
 * @property-read string $password CyberPanel admin password (sensitive)
 * @property-read bool|null $ssl_verify Whether to verify SSL certificates (default: true)
 */
class Configuration extends DataSet
{
    public static function rules(): Rules
    {
        return new Rules([
            'hostname' => ['required', 'string', 'regex:/^https?:\/\/.+/'],
            'username' => ['required', 'string', 'min:1'],
            'password' => ['required', 'string', 'min:1'],
            'ssl_verify' => ['nullable', 'boolean'],
        ]);
    }
}
