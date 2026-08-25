<?php

declare(strict_types=1);

namespace App\Domain\Nodes;

enum RoleName: string
{
    case Gateway = 'gateway';
    case Vpn = 'vpn';
    case AppDev = 'app-dev';
    case AppProd = 'app-prod';
}
