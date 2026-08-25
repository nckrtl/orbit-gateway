<?php

declare(strict_types=1);

namespace App\Infrastructure\Nodes;

use App\Domain\Nodes\NodeConverger;
use App\Domain\Nodes\NodeProvisioningException;
use App\Infrastructure\Ssh\HostKeyScanner;
use App\Infrastructure\Ssh\KnownHostsStore;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshConnection;
use App\Infrastructure\Ssh\SshExecutor;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Infrastructure\WireGuard\WireGuardPeerConverger;
use App\Models\Node;

/** @mago-expect lint:excessive-parameter-list */
final readonly class NativeNodeConverger implements NodeConverger
{
    public function __construct(
        private HostKeyScanner $hostKeys,
        private KnownHostsStore $knownHosts,
        private SshKeyProvider $sshKeys,
        private SshExecutor $ssh,
        private NodeBootstrapCommandFactory $bootstrapCommand,
        private WireGuardPeerConverger $wireGuard,
    ) {}

    public function converge(Node $node): void
    {
        $hostKey = $this->hostKeys->scan($node->public_ssh_host, $node->public_ssh_port);

        if (
            $node->ssh_host_fingerprint !== null
            && $node->ssh_host_fingerprint !== $hostKey->fingerprint
        ) {
            throw new NodeProvisioningException(
                step: 'ssh-host-key',
                errorCode: 'node.ssh_host_key_changed',
                message: "The SSH host key changed for node [{$node->name}].",
            );
        }

        $this->knownHosts->put($node->public_ssh_host, $node->public_ssh_port, $hostKey);
        $node->update([
            'ssh_host_key_type' => $hostKey->type,
            'ssh_host_key' => $hostKey->value,
            'ssh_host_fingerprint' => $hostKey->fingerprint,
        ]);

        $bootstrap = $this->ssh->execute(
            $this->connection($node, $node->ssh_user),
            $this->bootstrapCommand->make($node->loadMissing('roles')),
        );

        if (! $bootstrap->succeeded()) {
            throw new NodeProvisioningException(
                step: 'base-host',
                errorCode: 'node.bootstrap_failed',
                message: "Could not bootstrap node [{$node->name}].",
                result: $bootstrap,
            );
        }

        $verification = $this->ssh->execute(
            $this->connection($node, 'orbit'),
            new RemoteCommand(['true']),
        );

        if (! $verification->succeeded()) {
            throw new NodeProvisioningException(
                step: 'orbit-ssh',
                errorCode: 'node.orbit_ssh_failed',
                message: "Could not connect to node [{$node->name}] as orbit.",
                result: $verification,
            );
        }

        if (! is_string($node->wireguard_address)) {
            throw new NodeProvisioningException(
                step: 'wireguard-address',
                errorCode: 'vpn.peer_address_missing',
                message: "Node [{$node->name}] has no WireGuard address.",
            );
        }

        $wireguardAddress = $node->wireguard_address;
        $this->wireGuard->converge($node, $this->connection($node, 'orbit'));
        $this->knownHosts->put($wireguardAddress, 22, $hostKey);
        $privateVerification = $this->ssh->execute(
            $this->connection($node, 'orbit', $wireguardAddress, 22),
            new RemoteCommand(['true']),
        );

        if (! $privateVerification->succeeded()) {
            throw new NodeProvisioningException(
                step: 'wireguard-ssh',
                errorCode: 'vpn.peer_ssh_failed',
                message: "Could not reach node [{$node->name}] through WireGuard.",
                result: $privateVerification,
            );
        }

        $node->update(['ssh_user' => 'orbit']);
    }

    private function connection(
        Node $node,
        string $user,
        ?string $host = null,
        ?int $port = null,
    ): SshConnection {
        return new SshConnection(
            host: $host ?? $node->public_ssh_host,
            user: $user,
            port: $port ?? $node->public_ssh_port,
            identityFile: $this->sshKeys->privateKeyPath(),
            knownHostsFile: $this->knownHosts->path(),
        );
    }
}
