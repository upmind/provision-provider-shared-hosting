<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\Panelalpha\Data;

use Upmind\ProvisionBase\Provider\DataSet\DataSet;
use Upmind\ProvisionBase\Provider\DataSet\Rules;

/**
 * PanelAlpha API credentials.
 * @property-read string $hostname PanelAlpha server hostname
 * @property-read int|null $port PanelAlpha serves port
 * @property-read string $api_token PanelAlpha API key
 */
class Configuration extends DataSet
{
    public static function rules(): Rules
    {
        return new Rules([
            'hostname' => ['required', 'domain_name'],
            'port' => ['nullable', 'integer'],
            'api_token' => ['required', 'string']
        ]);
    }
}
