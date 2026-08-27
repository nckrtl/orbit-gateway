<?php

declare(strict_types=1);

namespace App\Infrastructure\Nodes\Roles;

use App\Domain\AppProd\AppProdCaddyManager;
use App\Domain\Nodes\NodeRoleFirewallManager;
use App\Domain\Nodes\RoleBaseline;
use App\Domain\Nodes\RoleName;
use App\Infrastructure\AppProd\AppProdSshExecutor;
use App\Models\Node;
use App\Models\NodeRole;

final readonly class AppProdRoleBaseline implements RoleBaseline
{
    public function __construct(
        private NodeRolePrerequisiteCommandFactory $commands,
        private AppProdSshExecutor $ssh,
        private AppProdCaddyManager $caddy,
        private NodeRoleFirewallManager $firewall,
    ) {}

    public function converge(Node $node, NodeRole $assignment): void
    {
        $this->ssh->execute(
            $node,
            $this->commands->make(RoleName::AppProd),
            'role-prerequisites',
            'app-prod.prerequisite_failed',
        );
        $this->caddy->converge($node);
        $this->firewall->converge($node, RoleName::AppProd);
    }

    public function remove(Node $node, NodeRole $assignment, bool $purgeData): void
    {
        $this->caddy->remove($node);
        $this->firewall->remove($node, RoleName::AppProd);
    }
}
