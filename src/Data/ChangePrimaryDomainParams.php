<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\Data;

use Upmind\ProvisionBase\Provider\DataSet\DataSet;
use Upmind\ProvisionBase\Provider\DataSet\Rules;

/**
 * Data used to set a new primary domain for an existing hosting account.
 *
 * @property-read string|integer|null $customer_id ID of the customer on the hosting platform
 * @property-read string|integer|null $subscription_id ID of the subscription on the hosting platform, if any
 * @property-read string $username Username of the account
 * @property-read string|null $domain Domain name for this account/subscription
 * @property-read string $new_domain New primary domain name to set for the account
 * @property-read bool|null $is_reseller Whether, or not, the account has reseller privileges
 */
class ChangePrimaryDomainParams extends DataSet
{
    public static function rules(): Rules
    {
        return new Rules([
            'customer_id' => ['nullable'],
            'subscription_id' => ['nullable'],
            'username' => ['required', 'string'],
            'domain' => ['nullable', 'domain_name'],
            'new_domain' => ['required', 'domain_name'],
            'is_reseller' => ['nullable', 'boolean'],
        ]);
    }
}
