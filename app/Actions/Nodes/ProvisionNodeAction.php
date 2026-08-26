<?php

declare(strict_types=1);

namespace App\Actions\Nodes;

use App\Data\Nodes\ProvisionNodeData;
use App\Domain\AppDev\PrivateDnsManager;
use App\Domain\Nodes\NodeConverger;
use App\Domain\Nodes\NodeProjectionOperationLock;
use App\Domain\Nodes\NodeProvisioningException;
use App\Domain\Nodes\NodeTld;
use App\Domain\Nodes\RoleAssignmentException;
use App\Domain\Nodes\RoleName;
use App\Domain\Nodes\RoleRegistry;
use App\Domain\Shared\LifecycleStatus;
use App\Domain\Shared\ResourceOperationException;
use App\Domain\WireGuard\GatewayPeerProjectionManager;
use App\Domain\WireGuard\WireGuardAddressAllocator;
use App\Domain\WireGuard\WireGuardEndpoint;
use App\Infrastructure\Ssh\SshHostKeyScanException;
use App\Models\Node;
use App\Models\NodeRole;
use Throwable;

/**
 * @mago-expect lint:cyclomatic-complexity Node provisioning keeps its ordered identity, role, and recovery gates together.
 * @mago-expect lint:kan-defect Node provisioning keeps its ordered identity, role, and recovery gates together.
 * @mago-expect lint:too-many-methods Node provisioning uses focused private guards around one ordered transaction-like flow.
 */
final readonly class ProvisionNodeAction
{
    /** @mago-expect lint:excessive-parameter-list Provisioning coordinates the existing explicit projection ports. */
    public function __construct(
        private AssignRoleAction $assignRole,
        private NodeConverger $converger,
        private WireGuardAddressAllocator $addresses,
        private PrivateDnsManager $dns,
        private NodeProjectionOperationLock $projectionLock,
        private GatewayPeerProjectionManager $peers,
        private RoleRegistry $roleRegistry,
    ) {}

    public function execute(ProvisionNodeData $data): Node
    {
        return $this->projectionLock->synchronized(fn (): Node => $this->executeLocked($data));
    }

    public function addRole(Node $node, RoleName $role): NodeRole
    {
        return $this->projectionLock->synchronized(function () use ($node, $role): NodeRole {
            $node->refresh();
            $existing = $node->roles()->where('role', $role->value)->first();

            if ($existing instanceof NodeRole) {
                return $existing->load('node');
            }

            $provisioned = $this->executeLocked(new ProvisionNodeData(
                name: $node->name,
                publicSshHost: $node->public_ssh_host,
                roles: [$role],
                publicSshPort: $node->public_ssh_port,
                sshUser: $node->ssh_user,
                wireguardAddress: $node->wireguard_address,
                wireguardPublicKey: $node->wireguard_public_key,
                wireguardEndpointOverride: $node->wireguard_endpoint_override,
                dnsServerOverride: $node->dns_server_override,
                expectedSshHostFingerprint: $node->ssh_host_fingerprint,
                platform: $node->platform,
                architecture: $node->architecture,
                tld: $node->tld,
            ));

            $assignment = $provisioned->roles()->where('role', $role->value)->sole();

            return $assignment->load('node');
        });
    }

    /** @mago-expect lint:halstead Ordered provisioning keeps persisted state and failure recovery in one transaction-like flow. */
    private function executeLocked(ProvisionNodeData $data): Node
    {
        $this->validateEndpointOverride($data);
        $node = Node::query()->firstOrNew(['name' => $data->name]);
        $this->guardProtectedState($node, $data);
        $platform = $this->platform($node, $data);
        $architecture = $this->architecture($node, $data);
        $this->validateRoleAssignments($node, $data);
        $tld = $this->tld($node, $data);
        $wireguardPublicKey = $this->wireguardPublicKey($node, $data, $platform);
        $sshUser = $this->sshUser($node, $data, $platform);

        if (
            $platform === 'linux'
            && $node->ssh_host_fingerprint === null
            && $data->expectedSshHostFingerprint === null
        ) {
            throw new ResourceOperationException(
                errorCode: 'node.ssh_host_fingerprint_required',
                message: "An expected SSH host fingerprint is required for node [{$data->name}].",
            );
        }

        $requestedAddress =
            $data->wireguardAddress ?? (is_string($node->wireguard_address) ? $node->wireguard_address : null);
        $wireguardAddress = $this->addresses->forProvisioning($requestedAddress, $node);
        $publicSshHost = $data->publicSshHost;

        if ($publicSshHost === '' && $node->exists && $node->public_ssh_host !== '') {
            $publicSshHost = $node->public_ssh_host;
        }

        if ($publicSshHost === '') {
            $publicSshHost = $wireguardAddress;
        }

        $node->fill([
            'status' => LifecycleStatus::Provisioning,
            'platform' => $platform,
            'architecture' => $architecture,
            'tld' => $tld,
            'public_ssh_host' => $publicSshHost,
            'public_ssh_port' => $node->exists ? $node->public_ssh_port : $data->publicSshPort,
            'ssh_user' => $sshUser,
            'wireguard_address' => $wireguardAddress,
            'wireguard_public_key' => $wireguardPublicKey,
            'wireguard_endpoint_override' => $data->wireguardEndpointOverride ?? $node->wireguard_endpoint_override,
            'dns_server_override' => $data->dnsServerOverride ?? $node->dns_server_override,
            'failed_step' => null,
            'error_code' => null,
        ])->save();

        try {
            foreach ($data->roles as $role) {
                $this->assignRole->execute($node, $role);
            }

            $node->roles()->update([
                'status' => LifecycleStatus::Provisioning,
                'failed_step' => null,
                'error_code' => null,
            ]);

            if ($platform === 'darwin' && $this->hasAppDevRole($node, $data)) {
                $this->convergeGatewayPeer($node);
                $this->convergePrivateDns($node);

                return $node->refresh()->load('roles');
            }

            $this->converger->converge($node, $data->expectedSshHostFingerprint);

            if ($this->hasAppDevRole($node, $data)) {
                $this->convergePrivateDns($node);
            }

            $node->update([
                'status' => LifecycleStatus::Active,
                'failed_step' => null,
                'error_code' => null,
            ]);
        } catch (NodeProvisioningException $exception) {
            $this->markFailed($node, $exception);

            throw $exception;
        } catch (SshHostKeyScanException $exception) {
            $failure = new NodeProvisioningException(
                step: 'ssh-host-key',
                errorCode: 'node.ssh_host_key_scan_failed',
                message: "Could not scan the SSH host key for node [{$node->name}].",
                previous: $exception,
                result: $exception->result,
            );
            $this->markFailed($node, $failure);

            throw $failure;
        } catch (Throwable $exception) {
            $failure = new NodeProvisioningException(
                step: 'unknown',
                errorCode: 'node.provision_failed',
                message: 'Node provisioning failed.',
                previous: $exception,
            );
            $this->markFailed($node, $failure);

            throw $failure;
        }

        $node->roles()->update([
            'status' => LifecycleStatus::Active,
            'failed_step' => null,
            'error_code' => null,
        ]);

        return $node->refresh()->load('roles');
    }

    private function tld(Node $node, ProvisionNodeData $data): ?string
    {
        $requested = $data->tld ?? (is_string($node->tld) ? $node->tld : null);

        if ($requested === null) {
            if (! $this->hasAppDevRole($node, $data)) {
                return null;
            }

            throw new ResourceOperationException(
                errorCode: 'node.tld_required',
                message: "An app-dev TLD is required for node [{$data->name}].",
            );
        }

        $tld = NodeTld::normalize($requested);

        if (! NodeTld::isValid($tld)) {
            throw new ResourceOperationException(
                errorCode: 'node.tld_invalid',
                message: "Node TLD [{$requested}] is invalid.",
            );
        }

        if (
            $node->exists
            && is_string($node->tld)
            && $node->tld !== $tld
            && $node->instances()->exists()
        ) {
            throw new ResourceOperationException(
                errorCode: 'node.tld_change_unsupported',
                message: "Node [{$data->name}] cannot change TLD while it owns instances.",
                status: 409,
            );
        }

        $taken = Node::query()
            ->where('tld', $tld)
            ->when($node->exists, static fn ($query) => $query->whereKeyNot($node->id))
            ->exists();

        if ($taken) {
            throw new ResourceOperationException(
                errorCode: 'node.tld_taken',
                message: "Node TLD [{$tld}] is already assigned.",
                status: 409,
            );
        }

        return $tld;
    }

    private function platform(Node $node, ProvisionNodeData $data): string
    {
        if ($node->exists && $node->platform !== '') {
            return $node->platform;
        }

        return $data->platform ?? 'linux';
    }

    private function architecture(Node $node, ProvisionNodeData $data): string
    {
        $architecture =
            $node->exists && is_string($node->architecture) && $node->architecture !== ''
                ? $node->architecture
                : $data->architecture;

        if ($architecture === null) {
            throw new ResourceOperationException(
                errorCode: 'node.architecture_required',
                message: "The real architecture is required for node [{$data->name}].",
            );
        }

        return $architecture;
    }

    private function hasAppDevRole(Node $node, ProvisionNodeData $data): bool
    {
        return (
            in_array(needle: RoleName::AppDev, haystack: $data->roles, strict: true)
            || $node->exists && $node->roles()->where('role', RoleName::AppDev->value)->exists()
        );
    }

    private function validateRoleAssignments(Node $node, ProvisionNodeData $data): void
    {
        foreach ($data->roles as $role) {
            if ($node->exists && $node->roles()->where('role', $role->value)->exists()) {
                continue;
            }

            if ($this->roleRegistry->definition($role)->singleton) {
                $assigned = NodeRole::query()
                    ->with('node')
                    ->where('role', $role->value)
                    ->first();

                if ($assigned instanceof NodeRole) {
                    throw new RoleAssignmentException(
                        "Role [{$role->value}] is already assigned to node [{$assigned->node->name}].",
                    );
                }
            }

            if (! $node->exists) {
                continue;
            }

            foreach ($node->roles()->get() as $assigned) {
                if ($this->roleRegistry->conflicts($role, $assigned->role)) {
                    throw new RoleAssignmentException(
                        "Role [{$role->value}] conflicts with assigned role [{$assigned->role->value}].",
                    );
                }
            }
        }
    }

    private function wireguardPublicKey(Node $node, ProvisionNodeData $data, string $platform): ?string
    {
        $stored = is_string($node->wireguard_public_key) ? $node->wireguard_public_key : null;
        $requested = $data->wireguardPublicKey;

        if ($requested !== null) {
            $decoded = base64_decode(string: $requested, strict: true);

            if ($decoded === false || strlen($decoded) !== 32 || base64_encode($decoded) !== $requested) {
                throw new ResourceOperationException(
                    errorCode: 'node.wireguard_public_key_invalid',
                    message: 'The WireGuard public key is invalid.',
                );
            }
        }

        if ($stored !== null && $requested !== null && $stored !== $requested) {
            throw new ResourceOperationException(
                errorCode: 'node.wireguard_public_key_changed',
                message: "The WireGuard public key for node [{$data->name}] cannot change.",
                status: 409,
            );
        }

        $publicKey = $requested ?? $stored;

        if ($platform === 'darwin' && $publicKey === null) {
            throw new ResourceOperationException(
                errorCode: 'node.wireguard_public_key_required',
                message: "A WireGuard public key is required for Darwin node [{$data->name}].",
            );
        }

        return $publicKey;
    }

    private function sshUser(Node $node, ProvisionNodeData $data, string $platform): string
    {
        $sshUser = $node->exists ? $node->ssh_user : $data->sshUser ?? 'root';

        if (
            $platform === 'darwin'
            && (preg_match('/\A[a-z_][a-z0-9_-]{0,63}\z/D', $sshUser) !== 1
            || in_array(needle: $sshUser, haystack: ['root', 'orbit'], strict: true))
        ) {
            throw new ResourceOperationException(
                errorCode: 'node.ssh_user_invalid',
                message: 'Darwin enrollment requires a canonical personal SSH user.',
            );
        }

        return $sshUser;
    }

    private function guardProtectedState(Node $node, ProvisionNodeData $data): void
    {
        if (
            ! $node->exists
            || $node->status !== LifecycleStatus::Active
            || $node->platform !== 'darwin'
            || ! $node
                ->roles()
                ->where('role', RoleName::AppDev->value)
                ->where('status', LifecycleStatus::Active->value)
                ->exists()
        ) {
            return;
        }

        $changed =
            $data->platform !== null && $data->platform !== $node->platform
            || $data->architecture !== null && $data->architecture !== $node->architecture
            || $data->tld !== null && NodeTld::normalize($data->tld) !== $node->tld
            || $data->sshUser !== null && $data->sshUser !== $node->ssh_user
            || $data->wireguardAddress !== null && $data->wireguardAddress !== $node->wireguard_address
            || $data->wireguardPublicKey !== null && $data->wireguardPublicKey !== $node->wireguard_public_key;

        if ($changed) {
            throw new ResourceOperationException(
                errorCode: 'node.protected_state_changed',
                message: "Protected setup inputs for Darwin node [{$node->name}] cannot change.",
                status: 409,
            );
        }
    }

    private function convergeGatewayPeer(Node $node): void
    {
        try {
            $this->peers->converge($node);
        } catch (Throwable $exception) {
            throw new NodeProvisioningException(
                step: 'wireguard-projection',
                errorCode: 'node.wireguard_projection_failed',
                message: 'Could not publish the node WireGuard peer projection.',
                previous: $exception,
            );
        }
    }

    private function convergePrivateDns(Node $pendingNode): void
    {
        try {
            $this->dns->converge($pendingNode);
        } catch (Throwable $exception) {
            throw new NodeProvisioningException(
                step: 'private-dns',
                errorCode: 'node.dns_projection_failed',
                message: 'Could not publish the node private DNS projection.',
                previous: $exception,
            );
        }
    }

    private function validateEndpointOverride(ProvisionNodeData $data): void
    {
        if (
            $data->wireguardEndpointOverride !== null
            && ! WireGuardEndpoint::isValid($data->wireguardEndpointOverride)
        ) {
            throw new ResourceOperationException(
                errorCode: 'vpn.endpoint_override_invalid',
                message: "WireGuard endpoint override [{$data->wireguardEndpointOverride}] is invalid.",
            );
        }
    }

    private function markFailed(Node $node, NodeProvisioningException $exception): void
    {
        $failure = [
            'status' => LifecycleStatus::Failed,
            'failed_step' => $exception->step,
            'error_code' => $exception->errorCode,
        ];

        $node->update($failure);
        $node->roles()->update($failure);
    }
}
