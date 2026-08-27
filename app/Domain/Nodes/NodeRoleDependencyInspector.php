<?php

declare(strict_types=1);

namespace App\Domain\Nodes;

use App\Models\Node;

interface NodeRoleDependencyInspector
{
    public function inspect(Node $node, RoleName $role): NodeRoleDependencySet;
}
