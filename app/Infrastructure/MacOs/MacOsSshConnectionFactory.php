<?php

declare(strict_types=1);

namespace App\Infrastructure\MacOs;

use App\Domain\Shared\ResourceOperationException;
use App\Infrastructure\Ssh\HostKeyScanner;
use App\Infrastructure\Ssh\KnownHostsStore;
use App\Infrastructure\Ssh\SshConnection;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Models\Node;
use Throwable;

final readonly class MacOsSshConnectionFactory
{
    public function __construct(
        private HostKeyScanner $hostKeys,
        private KnownHostsStore $knownHosts,
        private SshKeyProvider $sshKeys,
    ) {}

    public function make(Node $node): SshConnection
    {
        $address = $node->wireguard_address;

        if (
            $node->platform !== 'darwin'
            || ! is_string($address)
            || filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false
            || $node->ssh_user === ''
        ) {
            throw $this->unreachable();
        }

        try {
            $hostKey = $this->hostKeys->scan($address, 22);
        } catch (Throwable) {
            throw $this->unreachable();
        }

        if (
            $node->ssh_host_fingerprint !== null
            && $node->ssh_host_fingerprint !== $hostKey->fingerprint
            || $node->ssh_host_key_type !== null
            && $node->ssh_host_key_type !== $hostKey->type
            || $node->ssh_host_key !== null
            && $node->ssh_host_key !== $hostKey->value
        ) {
            throw new ResourceOperationException(
                errorCode: 'macos.verification_failed',
                message: 'The macOS SSH host key changed.',
                status: 502,
                safeDetails: ['check' => 'ssh-host-key'],
            );
        }

        try {
            $this->knownHosts->put($address, 22, $hostKey);
        } catch (Throwable) {
            throw new ResourceOperationException(
                errorCode: 'macos.verification_failed',
                message: 'The macOS SSH host key could not be pinned.',
                status: 502,
                safeDetails: ['check' => 'ssh-host-key'],
            );
        }
        $node->forceFill([
            'ssh_host_key_type' => $hostKey->type,
            'ssh_host_key' => $hostKey->value,
            'ssh_host_fingerprint' => $hostKey->fingerprint,
        ]);

        if ($node->exists) {
            $node->save();
        }

        return new SshConnection(
            host: $address,
            user: $node->ssh_user,
            port: 22,
            identityFile: $this->sshKeys->privateKeyPath(),
            knownHostsFile: $this->knownHosts->path(),
        );
    }

    private function unreachable(): ResourceOperationException
    {
        return new ResourceOperationException(
            errorCode: 'node.unreachable',
            message: 'The macOS node is not reachable over WireGuard SSH.',
            status: 502,
        );
    }
}
