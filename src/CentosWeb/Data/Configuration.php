<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\CentosWeb\Data;

use Upmind\ProvisionBase\Provider\DataSet\DataSet;
use Upmind\ProvisionBase\Provider\DataSet\Rules;

/**
 * CentosWeb API credentials.
 * @property-read string $hostname server hostname
 * @property-read string $api_key API key
 * @property-read string|null $shared_ip_address IP address to create new accounts on
 */
class Configuration extends DataSet
{
    public static function rules(): Rules
    {
        return new Rules([
            'hostname' => ['required', 'domain_name'],
            'api_key' => ['required', 'string'],
            'shared_ip_address' => ['required', 'ip'],
        ]);
    }
}
