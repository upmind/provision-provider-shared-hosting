<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\Data;

use Upmind\ProvisionBase\Provider\DataSet\DataSet;
use Upmind\ProvisionBase\Provider\DataSet\Rules;

/**
 * Hosting account usage data.
 *
 * @property-read UnitsConsumed|null $disk_mb Disk space used in MB
 * @property-read UnitsConsumed|null $bandwidth_mb Bandwidth used in MB
 * @property-read UnitsConsumed|null $inodes Number of inodes used
 * @property-read UnitsConsumed|null $websites Number of websites used
 * @property-read UnitsConsumed|null $mailboxes Number of mailboxes used
 * @property-read UnitsConsumed|null $subdomains Number of subdomains used
 * @property-read UnitsConsumed|null $addon_domains Number of addon domains used
 * @property-read UnitsConsumed|null $parked_domains Number of parked domains used
 */
class UsageData extends DataSet
{
    public static function rules(): Rules
    {
        return new Rules([
            'disk_mb' => ['nullable', UnitsConsumed::class],
            'bandwidth_mb' => ['nullable', UnitsConsumed::class],
            'inodes' => ['nullable', UnitsConsumed::class],
            'websites' => ['nullable', UnitsConsumed::class],
            'mailboxes' => ['nullable', UnitsConsumed::class],
            'subdomains' => ['nullable', UnitsConsumed::class],
            'addon_domains' => ['nullable', UnitsConsumed::class],
            'parked_domains' => ['nullable', UnitsConsumed::class],
        ]);
    }

    /**
     * @param UnitsConsumed|array|null $disk
     */
    public function setDiskMb($disk): self
    {
        $this->setValue('disk_mb', $disk);
        return $this;
    }

    /**
     * @param UnitsConsumed|array|null $bandwidth
     */
    public function setBandwidthMb($bandwidth): self
    {
        $this->setValue('bandwidth_mb', $bandwidth);
        return $this;
    }

    /**
     * @param UnitsConsumed|array|null $inodes
     */
    public function setInodes($inodes): self
    {
        $this->setValue('inodes', $inodes);
        return $this;
    }

    /**
     * @param UnitsConsumed|array|null $websites
     */
    public function setWebsites($websites): self
    {
        $this->setValue('websites', $websites);
        return $this;
    }

    /**
     * @param UnitsConsumed|array|null $mailboxes
     */
    public function setMailboxes($mailboxes): self
    {
        $this->setValue('mailboxes', $mailboxes);
        return $this;
    }

    /**
     * @param UnitsConsumed|array|null $subdomains
     */
    public function setSubdomains($subdomains): self
    {
        $this->setValue('subdomains', $subdomains);
        return $this;
    }

    /**
     * @param UnitsConsumed|array|null $addonDomains
     */
    public function setAddonDomains($addonDomains): self
    {
        $this->setValue('addon_domains', $addonDomains);
        return $this;
    }

    /**
     * @param UnitsConsumed|array|null $parkedDomains
     */
    public function setParkedDomains($parkedDomains): self
    {
        $this->setValue('parked_domains', $parkedDomains);
        return $this;
    }
}
