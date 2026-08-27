<?php

declare(strict_types=1);

namespace App\Infrastructure\Nodes\Roles;

use App\Domain\AppDev\AppDevCaddyManager;
use App\Domain\AppDev\PrivateDnsManager;
use App\Domain\Nodes\NodeRoleFirewallManager;
use App\Domain\Nodes\RoleBaseline;
use App\Domain\Nodes\RoleName;
use App\Infrastructure\AppDev\AppDevSshExecutor;
use App\Models\Node;
use App\Models\NodeRole;

final readonly class AppDevRoleBaseline implements RoleBaseline
{
    public function __construct(
        private NodeRolePrerequisiteCommandFactory $commands,
        private AppDevSshExecutor $ssh,
        private AppDevCaddyManager $caddy,
        private NodeRoleFirewallManager $firewall,
        private PrivateDnsManager $dns,
    ) {}

    public function converge(Node $node, NodeRole $assignment): void
    {
        $this->ssh->execute(
            $node,
            $this->commands->make(RoleName::AppDev),
            'role-prerequisites',
            'app-dev.prerequisite_failed',
        );
        $this->caddy->converge($node);
        $this->firewall->converge($node, RoleName::AppDev);
        $this->dns->converge($node);
    }

    public function remove(Node $node, NodeRole $assignment, bool $purgeData): void
    {
        $this->caddy->remove($node);
        $this->firewall->remove($node, RoleName::AppDev);
        $this->dns->converge();
    }
}
