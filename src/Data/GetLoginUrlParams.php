<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\Data;

use Upmind\ProvisionBase\Provider\DataSet\DataSet;
use Upmind\ProvisionBase\Provider\DataSet\Rules;

/**
 * Data for obtaining a pre-signed login URL, or a login token.
 *
 * @property-read string|integer|null $customer_id ID of the customer on the hosting platform
 * @property-read string|integer|null $subscription_id ID of the subscription on the hosting platform, if any
 * @property-read string $username Username of the account
 * @property-read string|null $domain Domain name for this account/subscription
 * @property-read string $user_ip IP of the person who wishes to log in
 * @property-read boolean|null $is_reseller Whether or not the account is a reseller
 * @property-read string|null $current_password current password for the username
 * @property-read SoftwareInstallationIdentifier|null $software
 * @property-read string|null $type Type of login to obtain, `url` (default) or `token`
 */
class GetLoginUrlParams extends DataSet
{
    public const TYPE_URL = 'url';
    public const TYPE_TOKEN = 'token';

    public static function rules(): Rules
    {
        return new Rules([
            'customer_id' => ['nullable'],
            'subscription_id' => ['nullable'],
            'username' => ['required', 'string'],
            'domain' => ['nullable', 'domain_name'],
            'user_ip' => ['required', 'ip'],
            'is_reseller' => ['boolean'],
            'software' => ['nullable', SoftwareInstallationIdentifier::class],
            'current_password' => ['nullable', 'string'],
            'type' => ['nullable', 'string', 'in:' . self::TYPE_URL . ',' . self::TYPE_TOKEN],
        ]);
    }

    /**
     * Whether a login token has been requested instead of a login URL.
     */
    public function wantsToken(): bool
    {
        return $this->type === self::TYPE_TOKEN;
    }
}
