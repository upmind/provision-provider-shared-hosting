<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\Data;

use Upmind\ProvisionBase\Provider\DataSet\DataSet;
use Upmind\ProvisionBase\Provider\DataSet\Rules;

/**
 * Limit and consumption of an arbitrary unit.
 *
 * @property-read int|float|null $used Units used
 * @property-read int|float|null $limit Units limit, or null for unlimited
 * @property-read string|null $used_pc Percentage of units used, e.g. "50.5%", or null if unlimited
 */
class UnitsConsumed extends DataSet
{
    public static function rules(): Rules
    {
        return new Rules([
            'used' => ['nullable', 'numeric'],
            'limit' => ['nullable', 'numeric'],
            'used_pc' => ['nullable', 'string', 'regex:/^\\d+(\\.\\d+)?%$/'],
        ]);
    }

    /**
     * @param int|float|null $used
     */
    public function setUsed($used): self
    {
        $this->setValue('used', $used);
        return $this->calculateUsedPc();
    }

    /**
     * @param int|float|null $limit
     */
    public function setLimit($limit): self
    {
        $this->setValue('limit', $limit);
        return $this->calculateUsedPc();
    }

    /**
     * @param string $usedPc Percentage of units used, e.g. "50.5%"
     */
    public function setUsedPc($usedPc): self
    {
        $this->setValue('used_pc', $usedPc);
        return $this;
    }

    /**
     * Calculate and set used_pc string based on the used and limit values.
     */
    public function calculateUsedPc(): self
    {
        if ($this->get('limit') === null) {
            $this->setUsedPc(null); // unlimited
            return $this;
        }

        if ((float) $this->get('limit') === 0.0) {
            $this->setUsedPc('100%'); // Forced to 100% for resource limits of 0
            return $this;
        }

        $this->setUsedPc(
            round($this->get('used') / $this->get('limit') * 100, 1) . '%'
        );
        return $this;
    }
}
