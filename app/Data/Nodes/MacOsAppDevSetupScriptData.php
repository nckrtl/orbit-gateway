<?php

declare(strict_types=1);

namespace App\Data\Nodes;

use Spatie\LaravelData\Data;

final class MacOsAppDevSetupScriptData extends Data
{
    public function __construct(
        public string $role,
        public string $summary,
        public string $script,
    ) {}
}
