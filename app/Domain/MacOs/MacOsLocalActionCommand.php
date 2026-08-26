<?php

declare(strict_types=1);

namespace App\Domain\MacOs;

enum MacOsLocalActionCommand: string
{
    case GatewayTrust = 'orbit gateway:trust';
}
