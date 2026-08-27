<?php

declare(strict_types=1);

namespace App\Infrastructure\Nodes\Roles;

use App\Domain\Nodes\NodeRoleFirewallManager;
use App\Domain\Nodes\NodeRoleValidationException;
use App\Domain\Nodes\RoleBaseline;
use App\Domain\Nodes\RoleName;
use App\Models\Node;
use App\Models\NodeRole;

final readonly class GatewayRoleBaseline implements RoleBaseline
{
    public function __construct(
        private NodeRoleFirewallManager $firewall,
    ) {}

    public function converge(Node $node, NodeRole $assignment): void
    {
        $this->firewall->converge($node, RoleName::Gateway);
    }

    public function remove(Node $node, NodeRole $assignment, bool $purgeData): never
    {
        throw new NodeRoleValidationException('The gateway role cannot be removed.');
    }
}
