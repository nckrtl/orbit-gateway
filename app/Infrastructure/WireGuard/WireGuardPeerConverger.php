<?php

declare(strict_types=1);

namespace App\Infrastructure\WireGuard;

use App\Infrastructure\Ssh\SshConnection;
use App\Models\Node;

interface WireGuardPeerConverger
{
    public function converge(Node $node, SshConnection $connection): void;
}
