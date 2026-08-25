<?php

declare(strict_types=1);

namespace App\Domain\Gateway;

use App\Data\Gateway\BootstrapGatewayData;
use App\Models\Node;

interface GatewayVpnConverger
{
    public function converge(Node $gateway, BootstrapGatewayData $data): void;
}
