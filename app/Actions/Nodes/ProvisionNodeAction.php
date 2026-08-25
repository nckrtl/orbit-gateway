<?php

declare(strict_types=1);

namespace App\Actions\Nodes;

use App\Data\Nodes\ProvisionNodeData;
use App\Domain\Nodes\NodeConverger;
use App\Domain\Nodes\NodeProvisioningException;
use App\Domain\Shared\LifecycleStatus;
use App\Domain\Shared\ResourceOperationException;
use App\Domain\WireGuard\WireGuardAddressAllocator;
use App\Models\Node;
use Throwable;

final readonly class ProvisionNodeAction
{
    public function __construct(
        private AssignRoleAction $assignRole,
        private NodeConverger $converger,
        private WireGuardAddressAllocator $addresses,
    ) {}

    public function execute(ProvisionNodeData $data): Node
    {
        $node = Node::query()->firstOrNew(['name' => $data->name]);

        if ($node->ssh_host_fingerprint === null && $data->expectedSshHostFingerprint === null) {
            throw new ResourceOperationException(
                errorCode: 'node.ssh_host_fingerprint_required',
                message: "An expected SSH host fingerprint is required for node [{$data->name}].",
            );
        }

        $requestedAddress =
            $data->wireguardAddress ?? (is_string($node->wireguard_address) ? $node->wireguard_address : null);
        $wireguardAddress = $this->addresses->forProvisioning($requestedAddress, $node);
        $node->fill([
            'status' => LifecycleStatus::Provisioning,
            'public_ssh_host' => $data->publicSshHost,
            'public_ssh_port' => $data->publicSshPort,
            'ssh_user' => $data->sshUser,
            'wireguard_address' => $wireguardAddress,
            'wireguard_endpoint_override' => $data->wireguardEndpointOverride,
            'dns_server_override' => $data->dnsServerOverride,
            'failed_step' => null,
            'error_code' => null,
        ])->save();

        try {
            foreach ($data->roles as $role) {
                $this->assignRole->execute($node, $role);
            }

            $this->converger->converge($node, $data->expectedSshHostFingerprint);
        } catch (NodeProvisioningException $exception) {
            $this->markFailed($node, $exception);

            throw $exception;
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

        $node->update([
            'status' => LifecycleStatus::Active,
            'failed_step' => null,
            'error_code' => null,
        ]);
        $node->roles()->update([
            'status' => LifecycleStatus::Active,
            'failed_step' => null,
            'error_code' => null,
        ]);

        return $node->refresh()->load('roles');
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
