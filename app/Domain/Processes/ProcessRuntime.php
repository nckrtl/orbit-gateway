<?php

declare(strict_types=1);

namespace App\Domain\Processes;

enum ProcessRuntime: string
{
    case Systemd = 'systemd';
    case Docker = 'docker';
}
