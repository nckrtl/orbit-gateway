<?php

declare(strict_types=1);

namespace App\Domain\Nodes;

use App\Models\Node;

interface NodeRoleFirewallManager
{
    public function convergeBase(Node $node): void;

    public function converge(Node $node, RoleName $role): void;

    public function remove(Node $node, RoleName $role): void;
}
