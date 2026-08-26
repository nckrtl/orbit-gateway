<?php

declare(strict_types=1);

namespace App\Actions\Nodes;

use App\Data\Nodes\ProvisionNodeData;
use App\Domain\AppDev\PrivateDnsManager;
use App\Domain\Nodes\NodeConverger;
use App\Domain\Nodes\NodeProvisioningException;
use App\Domain\Nodes\NodeTld;
use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Domain\Shared\ResourceOperationException;
use App\Domain\WireGuard\WireGuardAddressAllocator;
use App\Domain\WireGuard\WireGuardEndpoint;
use App\Infrastructure\Ssh\SshHostKeyScanException;
use App\Models\Node;
use Throwable;

/** @mago-expect lint:cyclomatic-complexity Node provisioning keeps its ordered identity, role, and recovery gates together. */
final readonly class ProvisionNodeAction
{
    public function __construct(
        private AssignRoleAction $assignRole,
        private NodeConverger $converger,
        private WireGuardAddressAllocator $addresses,
        private PrivateDnsManager $dns,
    ) {}

    /** @mago-expect lint:halstead Ordered provisioning keeps persisted state and failure recovery in one transaction-like flow. */
    public function execute(ProvisionNodeData $data): Node
    {
        $this->validateEndpointOverride($data);
        $node = Node::query()->firstOrNew(['name' => $data->name]);
        $platform = $this->platform($node, $data);
        $architecture = $this->architecture($node, $data);
        $tld = $this->tld($node, $data);

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
            'ssh_user' => $node->exists ? $node->ssh_user : $data->sshUser,
            'wireguard_address' => $wireguardAddress,
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
        $platform = $node->exists && $node->platform !== ''
            ? $node->platform
            : $data->platform;

        if ($platform !== 'linux') {
            throw new ResourceOperationException(
                errorCode: 'node.platform_unsupported',
                message: "Node platform [{$platform}] is not supported.",
            );
        }

        return $platform;
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
