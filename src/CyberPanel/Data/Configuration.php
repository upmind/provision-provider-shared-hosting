<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\CyberPanel\Data;

use Upmind\ProvisionBase\Provider\DataSet\DataSet;
use Upmind\ProvisionBase\Provider\DataSet\Rules;

/**
 * CyberPanel API credentials.
 *
 * @property-read string $hostname CyberPanel server hostname
 * @property-read int|null $port CyberPanel serves port
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
            'port' => ['nullable', 'integer'],
            'username' => ['required', 'string', 'min:1'],
            'password' => ['required', 'string', 'min:1'],
            'ssl_verify' => ['nullable', 'boolean'],
        ]);
    }

    public function getHostname(): string
    {
        return $this->hostname;
    }

    public function hasPort(): bool
    {
        return $this->getPort() !== null;
    }

    public function getPort(): ?int
    {
        return $this->port === null ? null : (int) $this->port;
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
