<?php

declare(strict_types=1);

namespace App\Domain\Settings;

enum SettingValueProtection
{
    case Plain;
    case Secret;
}
