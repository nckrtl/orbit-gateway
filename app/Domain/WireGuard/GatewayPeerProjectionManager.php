<?php

declare(strict_types=1);

namespace App\Domain\WireGuard;

use App\Models\Node;

interface GatewayPeerProjectionManager
{
    public function converge(Node $node): void;

    public function remove(Node $node): void;

    public function restore(Node $node): void;
}
