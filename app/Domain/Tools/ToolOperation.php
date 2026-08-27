<?php

declare(strict_types=1);

namespace App\Domain\Tools;

enum ToolOperation: string
{
    case Install = 'install';
    case Update = 'update';
    case Remove = 'remove';
}
