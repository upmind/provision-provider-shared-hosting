<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\Webuzo\Data;

use Upmind\ProvisionBase\Provider\DataSet\DataSet;
use Upmind\ProvisionBase\Provider\DataSet\Rules;

/**
 * Webuzo API credentials.
 * @property-read string $hostname API hostname
 * @property-read string $api_key API key
 * @property-read string $username Username
 * @property-read string $password Password
 */
class Configuration extends DataSet
{
    public static function rules(): Rules
    {
        return new Rules([
            'hostname' => ['required', 'string'],
            'api_key' => ['required_without_all:username,password', 'nullable', 'string'],
            'username' => ['required_without:api_key', 'nullable', 'string'],
            'password' => ['required_without:api_key', 'nullable', 'string'],
        ]);
    }
}
