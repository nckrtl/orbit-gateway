<?php

declare(strict_types=1);

namespace App\Domain\Tools;

enum ToolManagerName: string
{
    case Apt = 'apt';
    case Vp = 'vp';
    case Composer = 'composer';
}
