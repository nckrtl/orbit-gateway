<?php

declare(strict_types=1);

namespace App\Domain\Settings;

final readonly class SettingScope
{
    public function __construct(
        public SettingScopeType $type,
        public int $id = 0,
    ) {}
}
