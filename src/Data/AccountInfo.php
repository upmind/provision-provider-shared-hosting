<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\Data;

use Upmind\ProvisionBase\Provider\DataSet\ResultData;
use Upmind\ProvisionBase\Provider\DataSet\Rules;

/**
 * Result set encapsulating the info/data about a created hosting account.
 *
 * @property-read string|null $service_identifier Human-readable identifier/label for the account
 * @property-read string|integer|null $customer_id ID of the customer on the hosting platform
 * @property-read string|integer|null $subscription_id ID of the subscription on the hosting platform, if any
 * @property-read string $username Username of the account
 * @property-read string|null $domain Main domain name of the account
 * @property-read bool|null $reseller Whether or not the account has reseller privileges
 * @property-read string $server_hostname Hostname of the server the account is on
 * @property-read string $package_name Account package/plan name/identifier
 * @property-read bool $suspended Whether or not the account is suspended
 * @property-read string|null $suspend_reason Reason for suspension
 * @property-read string|null $ip Account ip address
 * @property-read string[]|null $nameservers
 * @property-read SoftwareInstallation|null $software
 * @property-read string|null $location
 */
class AccountInfo extends ResultData
{
    public static function rules(): Rules
    {
        return new Rules([
            'service_identifier' => ['nullable', 'string'],
            'customer_id' => ['nullable'],
            'subscription_id' => ['nullable'],
            'username' => ['required', 'string'],
            'domain' => ['nullable', 'domain_name'],
            'reseller' => ['nullable', 'boolean'],
            'server_hostname' => ['required', 'domain_name'],
            'package_name' => ['required', 'string'],
            'suspended' => ['required', 'boolean'],
            'suspend_reason' => ['nullable', 'string'],
            'ip' => ['nullable', 'ip'],
            'nameservers' => ['nullable', 'array'],
            'nameservers.*' => ['string'],
            'software' => ['nullable', SoftwareInstallation::class],
            'location' => ['nullable', 'string'],
        ]);
    }

    /**
     * @param string $username Username of the account
     */
    public function setUsername(string $username): self
    {
        $this->setValue('username', $username);
        return $this;
    }

    /**
     * @param string|int|null $customerId Customer ID on the hosting platform
     */
    public function setCustomerId($customerId): self
    {
        $this->setValue('customer_id', $customerId);
        return $this;
    }

    /**
     * @param string|int|null $subscriptionId ID of the subscription on the hosting platform, if any
     */
    public function setSubscriptionId($subscriptionId): self
    {
        $this->setValue('subscription_id', $subscriptionId);
        return $this;
    }

    /**
     * @param string|null $domain Main domain name of the account
     */
    public function setDomain(?string $domain): self
    {
        $this->setValue('domain', $domain);
        return $this;
    }

    /**
     * @param string|null $serviceIdentifier Service identifier for the account
     */
    public function setServiceIdentifier(?string $serviceIdentifier): self
    {
        $this->setValue('service_identifier', $serviceIdentifier);
        return $this;
    }

    /**
     * @param bool $reseller Whether or not the account has reseller privileges
     */
    public function setReseller(?bool $reseller): self
    {
        $this->setValue('reseller', $reseller);
        return $this;
    }

    /**
     * @param string $hostname Configuration server hostname
     */
    public function setServerHostname(string $hostname): self
    {
        $this->setValue('server_hostname', $hostname);
        return $this;
    }

    /**
     * @param string $packageName Account package name
     */
    public function setPackageName(string $packageName): self
    {
        $this->setValue('package_name', $packageName);
        return $this;
    }

    /**
     * @param bool $suspended Whether or not account is suspended
     */
    public function setSuspended(bool $suspended): self
    {
        $this->setValue('suspended', $suspended);
        return $this;
    }

    /**
     * @param string $reason Reason for suspension
     */
    public function setSuspendReason(?string $reason): self
    {
        $this->setValue('suspend_reason', $reason);
        return $this;
    }

    /**
     * @param string|null $ip Account ip address
     */
    public function setIp(?string $ip): self
    {
        $this->setValue('ip', $ip);
        return $this;
    }

    /**
     * @param string[]|null[]|null
     */
    public function setNameservers(?array $nameservers): self
    {
        if (is_array($nameservers)) {
            // sort, filter and reset array keys
            natsort($nameservers);
            $nameservers = array_values(array_filter($nameservers));
        }

        $this->setValue('nameservers', $nameservers);
        return $this;
    }

    /**
     * @param SoftwareInstallation|array|null $installation
     */
    public function setSoftware($installation): self
    {
        $this->setValue('software', $installation);
        return $this;
    }

    /**
     * @param string $location
     * @return $this
     */
    public function setLocation(?string $location): self
    {
        $this->setValue('location', $location);
        return $this;
    }
}
