<?php

declare(strict_types=1);

namespace App\Domain\MacOs;

final readonly class MacOsAppDevSetupPlan
{
    public function __construct(
        public string $summary,
        public string $script,
    ) {}
}
