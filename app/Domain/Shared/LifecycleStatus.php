<?php

declare(strict_types=1);

namespace App\Domain\Shared;

enum LifecycleStatus: string
{
    case Provisioning = 'provisioning';
    case Active = 'active';
    case Failed = 'failed';
    case Removing = 'removing';
}
