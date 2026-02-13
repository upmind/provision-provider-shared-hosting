<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\CyberPanel\Data;

use Upmind\ProvisionBase\Provider\DataSet\DataSet;
use Upmind\ProvisionBase\Provider\DataSet\Rules;

/**
 * CyberPanel API credentials.
 *
 * @property-read string $hostname CyberPanel server hostname
 * @property-read string $username CyberPanel admin username
 * @property-read string $password CyberPanel admin password (sensitive)
 * @property-read bool|null $ssl_verify Whether to verify SSL certificates (default: false)
 */
class Configuration extends DataSet
{
    public static function rules(): Rules
    {
        return new Rules([
            'hostname' => ['required', 'string', 'domain_name'],
            'username' => ['required', 'string', 'min:1'],
            'password' => ['required', 'string', 'min:1'],
            'ssl_verify' => ['nullable', 'boolean'],
        ]);
    }

    public function getHostname(): string
    {
        return $this->hostname;
    }

    public function getUsername(): string
    {
        return $this->username;
    }

    public function getPassword(): string
    {
        return $this->password;
    }

    public function shouldVerifySsl(): bool
    {
        return (bool) $this->ssl_verify;
    }
}
