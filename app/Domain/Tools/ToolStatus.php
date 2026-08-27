<?php

declare(strict_types=1);

namespace App\Domain\Tools;

enum ToolStatus: string
{
    case Installing = 'installing';
    case Installed = 'installed';
    case Updating = 'updating';
    case Removing = 'removing';
    case Failed = 'failed';
}
