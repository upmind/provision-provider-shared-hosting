<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\Enhance\Data;

use Upmind\ProvisionBase\Provider\DataSet\DataSet;
use Upmind\ProvisionBase\Provider\DataSet\Rules;

/**
 * Enhance API credentials.
 *
 * @property-read string $hostname Enhance server hostname
 * @property-read string $org_id Enhance organisation id
 * @property-read string $access_token API access token
 * @property-read string|null $sso_destination Which control panel to log into, either Enhance or Wordpress
 * @property-read bool|null $ignore_ssl_errors When set to true, SSL will not be verified
 * @property-read bool|null $create_subscription_only When enabled, create() creates a subscription without creating a website
 * @property-read bool $remove_www Whether or not to strip www. from domain names when creating new subscriptions
 * @property-read string|null $dedicated_server_group Server group to check when creating dedicated plans with a given server id
 * @property-read bool|null $debug Whether or not to enable debug logging of API requests
 */
class Configuration extends DataSet
{
    public static function rules(): Rules
    {
        return new Rules([
            'hostname' => ['required', 'domain_name'],
            'org_id' => ['required', 'string'],
            'access_token' => ['required', 'string'],
            'sso_destination' => ['in:enhance,wordpress'],
            'ignore_ssl_errors' => ['boolean'],
            'create_subscription_only' => ['boolean'],
            'remove_www' => ['boolean'],
            'dedicated_server_group' => ['nullable', 'string'],
            'debug' => ['boolean'],
        ]);
    }
}
