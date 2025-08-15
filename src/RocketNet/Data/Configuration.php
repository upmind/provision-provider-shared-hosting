<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\RocketNet\Data;

use Upmind\ProvisionBase\Provider\DataSet\DataSet;
use Upmind\ProvisionBase\Provider\DataSet\Rules;

/**
 * RocketNet API credentials.
 * @property-read string $username RocketNet username
 * @property-read string $password RocketNet password
 * @property-read string $hostname RocketNet hostname
 */
class Configuration extends DataSet
{
    public static function rules(): Rules
    {
        return new Rules([
            'username' => ['required', 'string'],
            'password' => ['required', 'string'],
            'hostname' => ['required', 'domain_name'],
        ]);
    }
}
