<?php

declare(strict_types=1);

namespace Upmind\ProvisionProviders\SharedHosting\Koapanel;

use RuntimeException;
use Throwable;

/**
 * An error answered by the panel, or a network failure (status 0).
 */
class ApiError extends RuntimeException
{
    public function __construct(
        public readonly int $status,
        public readonly string $errorCode,
        string $message,
        public readonly ?string $field = null,
        ?Throwable $previous = null
    ) {
        parent::__construct($message, $status, $previous);
    }
}
