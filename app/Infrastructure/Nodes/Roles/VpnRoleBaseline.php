<?php

declare(strict_types=1);

namespace App\Infrastructure\Nodes\Roles;

use App\Domain\Nodes\NodeRoleFirewallManager;
use App\Domain\Nodes\NodeRoleOperationException;
use App\Domain\Nodes\NodeRoleValidationException;
use App\Domain\Nodes\RoleBaseline;
use App\Domain\Nodes\RoleName;
use App\Infrastructure\Ssh\KnownHostsStore;
use App\Infrastructure\Ssh\SshConnection;
use App\Infrastructure\Ssh\SshExecutor;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Models\Node;
use App\Models\NodeRole;

final readonly class VpnRoleBaseline implements RoleBaseline
{
    public function __construct(
        private NodeRolePrerequisiteCommandFactory $commands,
        private SshExecutor $ssh,
        private SshKeyProvider $keys,
        private KnownHostsStore $knownHosts,
        private NodeRoleFirewallManager $firewall,
    ) {}

    public function converge(Node $node, NodeRole $assignment): void
    {
        if (! is_string($node->wireguard_address) || $node->wireguard_address === '') {
            throw new NodeRoleOperationException(
                'role-prerequisites',
                'node_role.convergence_failed',
                'vpn.wireguard_address_missing',
                "Node [{$node->name}] has no WireGuard address.",
            );
        }

        $result = $this->ssh->execute(
            new SshConnection(
                $node->wireguard_address,
                'orbit',
                22,
                $this->keys->privateKeyPath(),
                $this->knownHosts->path(),
            ),
            $this->commands->make(RoleName::Vpn),
        );

        if (! $result->succeeded()) {
            throw new NodeRoleOperationException(
                'role-prerequisites',
                'node_role.convergence_failed',
                'vpn.prerequisite_failed',
                "VPN role prerequisites failed on node [{$node->name}].",
                $result,
            );
        }

        $this->firewall->converge($node, RoleName::Vpn);
    }

    public function remove(Node $node, NodeRole $assignment, bool $purgeData): never
    {
        throw new NodeRoleValidationException('The VPN role cannot be removed.');
    }
}
