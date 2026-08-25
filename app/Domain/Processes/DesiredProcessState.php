<?php

declare(strict_types=1);

namespace App\Domain\Processes;

enum DesiredProcessState: string
{
    case Running = 'running';
    case Stopped = 'stopped';
}
