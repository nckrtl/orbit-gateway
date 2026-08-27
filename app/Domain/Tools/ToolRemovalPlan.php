<?php

declare(strict_types=1);

namespace App\Domain\Tools;

final readonly class ToolRemovalPlan
{
    /** @param list<string> $packages */
    public function __construct(
        public array $packages,
    ) {}

    public function removesOnly(string $package): bool
    {
        return $this->packages === [$package];
    }
}
