<?php

declare(strict_types=1);

namespace App\Actions\Nodes;

use App\Domain\Nodes\RoleName;
use App\Models\Node;
use App\Models\NodeRole;

final readonly class AddNodeRoleAction
{
    public function __construct(
        private ProvisionNodeAction $provisionNode,
    ) {}

    public function execute(Node $node, RoleName $role): NodeRole
    {
        return $this->provisionNode->addRole($node, $role);
    }
}
