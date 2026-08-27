<?php

declare(strict_types=1);

namespace App\Infrastructure\Nodes;

use App\Domain\Firewall\FirewallOperationException;
use App\Domain\Nodes\NodeConverger;
use App\Domain\Nodes\NodeProvisioningException;
use App\Domain\Nodes\NodeRoleFirewallManager;
use App\Infrastructure\Ssh\HostKeyScanner;
use App\Infrastructure\Ssh\KnownHostsStore;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshConnection;
use App\Infrastructure\Ssh\SshExecutor;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Infrastructure\WireGuard\WireGuardPeerConverger;
use App\Models\Node;

/** @mago-expect lint:excessive-parameter-list Base convergence requires each typed host boundary. */
final readonly class NativeNodeConverger implements NodeConverger
{
    public function __construct(
        private HostKeyScanner $hostKeys,
        private KnownHostsStore $knownHosts,
        private SshKeyProvider $sshKeys,
        private SshExecutor $ssh,
        private NodeBootstrapCommandFactory $bootstrapCommand,
        private WireGuardPeerConverger $wireGuard,
        private NodeRoleFirewallManager $firewall,
    ) {}

    public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void
    {
        if ($node->platform !== 'linux') {
            throw new NodeProvisioningException(
                'platform',
                'node.platform_unsupported',
                "Node platform [{$node->platform}] has no provisioning adapter.",
            );
        }

        $hostKey = $this->hostKeys->scan($node->public_ssh_host, $node->public_ssh_port);

        if ($node->ssh_host_fingerprint !== null && $node->ssh_host_fingerprint !== $hostKey->fingerprint) {
            throw new NodeProvisioningException(
                'ssh-host-key',
                'node.ssh_host_key_changed',
                "The SSH host key changed for node [{$node->name}].",
            );
        }

        if ($node->ssh_host_fingerprint === null && $expectedSshHostFingerprint === null) {
            throw new NodeProvisioningException(
                'ssh-host-key',
                'node.ssh_host_fingerprint_required',
                "An expected SSH host fingerprint is required for node [{$node->name}].",
            );
        }

        if ($expectedSshHostFingerprint !== null && ! hash_equals($expectedSshHostFingerprint, $hostKey->fingerprint)) {
            throw new NodeProvisioningException(
                'ssh-host-key',
                'node.ssh_host_key_mismatch',
                "The SSH host fingerprint did not match for node [{$node->name}].",
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
            $node->ssh_user === 'orbit'
                ? $this->bootstrapCommand->makeWithPasswordlessSudo($node)
                : $this->bootstrapCommand->make($node),
        );

        if (! $bootstrap->succeeded()) {
            throw new NodeProvisioningException(
                'base-host',
                'node.bootstrap_failed',
                "Could not bootstrap node [{$node->name}].",
                result: $bootstrap,
            );
        }

        $verification = $this->ssh->execute($this->connection($node, 'orbit'), new RemoteCommand(['true']));

        if (! $verification->succeeded()) {
            throw new NodeProvisioningException(
                'orbit-ssh',
                'node.orbit_ssh_failed',
                "Could not connect to node [{$node->name}] as orbit.",
                result: $verification,
            );
        }

        if (! is_string($node->wireguard_address)) {
            throw new NodeProvisioningException(
                'wireguard-address',
                'vpn.peer_address_missing',
                "Node [{$node->name}] has no WireGuard address.",
            );
        }

        $wireguardAddress = $node->wireguard_address;

        try {
            $this->firewall->convergeBase($node);
        } catch (FirewallOperationException $exception) {
            throw new NodeProvisioningException(
                $exception->step,
                $exception->errorCode,
                $exception->getMessage(),
                $exception,
                $exception->result,
            );
        }

        $this->wireGuard->converge($node, $this->connection($node, 'orbit'));
        $this->knownHosts->put($wireguardAddress, 22, $hostKey);
        $privateVerification = $this->ssh->execute(
            $this->connection($node, 'orbit', $wireguardAddress, 22),
            new RemoteCommand(['true']),
        );

        if (! $privateVerification->succeeded()) {
            throw new NodeProvisioningException(
                'wireguard-ssh',
                'vpn.peer_ssh_failed',
                "Could not reach node [{$node->name}] through WireGuard.",
                result: $privateVerification,
            );
        }

        $node->update(['ssh_user' => 'orbit']);
    }

    private function connection(Node $node, string $user, ?string $host = null, ?int $port = null): SshConnection
    {
        return new SshConnection(
            host: $host ?? $node->public_ssh_host,
            user: $user,
            port: $port ?? $node->public_ssh_port,
            identityFile: $this->sshKeys->privateKeyPath(),
            knownHostsFile: $this->knownHosts->path(),
        );
    }
}
