<?php

declare(strict_types=1);

namespace App\Actions\Nodes;

use App\Data\Nodes\RemoveNodeData;
use App\Domain\AppDev\PrivateDnsManager;
use App\Domain\Nodes\NodeProjectionOperationLock;
use App\Domain\Nodes\NodeProvisioningException;
use App\Domain\Nodes\NodeRemovalException;
use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Domain\Shared\ResourceOperationException;
use App\Domain\WireGuard\GatewayPeerProjectionManager;
use App\Models\Node;
use Throwable;

/** @mago-expect lint:cyclomatic-complexity Removal keeps guarded projection rollback in one transaction flow. */
final readonly class RemoveNodeAction
{
    public function __construct(
        private PrivateDnsManager $dns,
        private GatewayPeerProjectionManager $peers,
        private NodeProjectionOperationLock $projectionLock,
    ) {}

    public function execute(Node $node, Node $caller): RemoveNodeData
    {
        return $this->projectionLock->synchronized(
            fn (): RemoveNodeData => $this->executeLocked($node, $caller),
        );
    }

    private function executeLocked(Node $node, Node $caller): RemoveNodeData
    {
        $node->refresh();
        $caller->refresh();
        $this->guardRemoval($node, $caller);
        $peerRemoved = false;
        $result = new RemoveNodeData(
            id: $node->id,
            name: $node->name,
            removed: true,
            wireguardPeerRemoved: $node->wireguard_public_key !== null,
            dnsRecordsRemoved: true,
        );
        $node->update(['status' => LifecycleStatus::Removing]);

        if ($node->wireguard_public_key !== null) {
            try {
                $this->peers->remove($node);
                $peerRemoved = true;
            } catch (Throwable $exception) {
                $node->update(['status' => LifecycleStatus::Active]);

                throw $this->failure(
                    step: 'wireguard-projection',
                    errorCode: 'node.wireguard_projection_failed',
                    message: "Could not remove the WireGuard peer for node [{$node->name}].",
                    previous: $exception,
                );
            }
        }

        try {
            $this->dns->converge();
        } catch (Throwable $exception) {
            $node->update(['status' => LifecycleStatus::Active]);

            if ($peerRemoved) {
                try {
                    $this->peers->restore($node);
                } catch (Throwable $rollbackException) {
                    throw $this->failure(
                        step: 'wireguard-rollback',
                        errorCode: 'node.removal_rollback_failed',
                        message: "Could not restore the WireGuard peer for node [{$node->name}].",
                        previous: $rollbackException,
                    );
                }
            }

            throw $this->failure(
                step: 'dns-projection',
                errorCode: 'node.dns_projection_failed',
                message: "Could not remove the DNS records for node [{$node->name}].",
                previous: $exception,
            );
        }

        try {
            $node->delete();
        } catch (Throwable $exception) {
            $node->update(['status' => LifecycleStatus::Active]);
            $rollbackFailure = null;

            if ($peerRemoved) {
                try {
                    $this->peers->restore($node);
                } catch (Throwable $peerRollbackException) {
                    $rollbackFailure = $peerRollbackException;
                }
            }

            try {
                $this->dns->converge();
            } catch (Throwable $dnsRollbackException) {
                $rollbackFailure ??= $dnsRollbackException;
            }

            if ($rollbackFailure instanceof Throwable) {
                throw $this->failure(
                    step: 'persistence-rollback',
                    errorCode: 'node.removal_rollback_failed',
                    message: "Could not restore network projections for node [{$node->name}].",
                    previous: $rollbackFailure,
                );
            }

            throw $this->failure(
                step: 'persistence',
                errorCode: 'node.persistence_failed',
                message: "Could not remove node [{$node->name}] from gateway state.",
                previous: $exception,
            );
        }

        return $result;
    }

    private function guardRemoval(Node $node, Node $caller): void
    {
        if ($node->is($caller)) {
            throw $this->conflict('node.self_removal_forbidden', 'A node cannot remove itself.');
        }

        if ($node->roles()->where('role', RoleName::Gateway->value)->exists()) {
            throw $this->conflict('node.gateway_removal_forbidden', 'The gateway node cannot be removed.');
        }

        if ($node->roles()->where('role', RoleName::Vpn->value)->exists()) {
            throw $this->conflict('node.vpn_removal_forbidden', 'The VPN node cannot be removed.');
        }

        if ($node->roles()->exists()) {
            throw $this->conflict('node.has_roles', "Node [{$node->name}] still has roles.");
        }

        if ($node->instances()->exists()) {
            throw $this->conflict('node.has_instances', "Node [{$node->name}] still has instances.");
        }

        if ($node->firewallRules()->exists()) {
            throw $this->conflict('node.has_firewall_rules', "Node [{$node->name}] still has firewall rules.");
        }
    }

    private function conflict(string $errorCode, string $message): ResourceOperationException
    {
        return new ResourceOperationException($errorCode, $message, 409);
    }

    private function failure(
        string $step,
        string $errorCode,
        string $message,
        Throwable $previous,
    ): NodeRemovalException {
        $result = $previous instanceof NodeProvisioningException ? $previous->result : null;

        return new NodeRemovalException($step, $errorCode, $message, $result, $previous);
    }
}
