<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\Data;

use Carbon\Carbon;
use DateTime;
use Upmind\ProvisionBase\Provider\DataSet\ResultData;
use Upmind\ProvisionBase\Provider\DataSet\Rules;

/**
 * Data set encapsulating a login url or login token.
 *
 * @property-read string|null $type Type of login returned, `url` or `token`
 * @property-read string|null $login_url Pre-signed url which can be used to sign in
 * @property-read string|null $token Token which can be used to sign in
 * @property-read string|null $for_ip IP address the url/token is valid for, if any
 * @property-read string|null $expires Date/time the url/token expires, in UTC format `Y-m-d H:i:s`
 * @property-read array|null $post_fields Post fields with user and password
 */
class LoginUrl extends ResultData
{
    public static function rules(): Rules
    {
        return new Rules([
            'type' => [
                'nullable',
                'string',
                'in:' . GetLoginUrlParams::TYPE_URL . ',' . GetLoginUrlParams::TYPE_TOKEN,
            ],
            'login_url' => ['required_without:token', 'nullable', 'url'],
            'token' => ['required_without:login_url', 'nullable', 'string'],
            'for_ip' => ['nullable', 'ip'],
            'expires' => ['nullable', 'date_format:Y-m-d H:i:s'],
            'post_fields' => ['nullable', 'array'],
        ]);
    }

    /**
     * @param string|null $type Type of login returned, `url` or `token`
     */
    public function setType(?string $type): self
    {
        $this->setValue('type', $type);
        return $this;
    }

    /**
     * @param string $url Pre-signed url which can be used to sign in
     */
    public function setLoginUrl(string $url): self
    {
        $this->setValue('login_url', $url);

        if (!isset($this->type)) {
            $this->setType(GetLoginUrlParams::TYPE_URL);
        }

        return $this;
    }

    /**
     * @param string $token Token which can be used to sign in
     */
    public function setToken(string $token): self
    {
        $this->setValue('token', $token);
        $this->setType(GetLoginUrlParams::TYPE_TOKEN);
        return $this;
    }

    /**
     * @param string|null $ip IP address the url/token is valid for
     */
    public function setForIp(?string $ip): self
    {
        $this->setValue('for_ip', $ip);
        return $this;
    }

    /**
     * @param Carbon|DateTime $expires Datetime the url/token expires
     */
    public function setExpires(?DateTime $expires): self
    {
        $this->setValue('expires', $expires ? $expires->format('Y-m-d H:i:s') : null);
        return $this;
    }

    /**
     * @param array|null $data
     * @return $this
     */
    public function setPostFields(?array $data): self
    {
        $this->setValue('post_fields', $data);
        return $this;
    }
}
