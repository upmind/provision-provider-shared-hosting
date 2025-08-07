<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\Webuzo\Data;

use Upmind\ProvisionBase\Provider\DataSet\DataSet;
use Upmind\ProvisionBase\Provider\DataSet\Rules;

/**
 * Webuzo API credentials.
 *
 * @property-read string $authentication_type Authentication type, either 'api_credentials' or 'login_credentials'
 * @property-read string $hostname API hostname
 * @property-read string $username Username
 * @property-read string|null $api_key API key
 * @property-read string|null $password Password
 */
class Configuration extends DataSet
{
    public static function rules(): Rules
    {
        return new Rules([
            'authentication_type' => ['required', 'string', 'in:api_credentials,login_credentials'],
            'hostname' => ['required', 'string'],
            'username' => ['required', 'string'],
            'api_key' => ['required_if:authentication_type,api_credentials', 'nullable', 'string'],
            'password' => ['required_if:authentication_type,login_credentials', 'nullable', 'string'],
        ]);
    }

    public function authenticateWithBasicAuth()
    {
        return $this->authentication_type === 'login_credentials';
    }

    public function authenticateWithApiKey()
    {
        return $this->authentication_type === 'api_credentials';
    }
}
