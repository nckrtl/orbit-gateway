<?php

declare(strict_types=1);

namespace App\Infrastructure\Processes;

use Closure;
use RuntimeException;

final class CommandDeadline
{
    private ?float $expiresAt = null;

    /** @var Closure(): float */
    private readonly Closure $clock;

    /** @param (Closure(): float)|null $clock */
    public function __construct(?Closure $clock = null)
    {
        $this->clock = $clock ?? static fn (): float => microtime(true);
    }

    public function start(float $seconds): void
    {
        $this->expiresAt = ($this->clock)() + $seconds;
    }

    public function clear(): void
    {
        $this->expiresAt = null;
    }

    public function cap(float $localTimeout): float
    {
        if ($this->expiresAt === null) {
            return $localTimeout;
        }

        $remaining = $this->expiresAt - ($this->clock)();

        if ($remaining <= 0.0) {
            throw new RuntimeException('The 900-second API command deadline was exceeded.');
        }

        return min($localTimeout, $remaining);
    }
}
