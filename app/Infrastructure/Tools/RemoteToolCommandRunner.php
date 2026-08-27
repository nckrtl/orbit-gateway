<?php

declare(strict_types=1);

namespace App\Infrastructure\Tools;

use App\Domain\Tools\ToolManagerException;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Ssh\KnownHostsStore;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshConnection;
use App\Infrastructure\Ssh\SshExecutor;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Models\Node;

final readonly class RemoteToolCommandRunner
{
    public function __construct(
        private SshExecutor $ssh,
        private SshKeyProvider $keys,
        private KnownHostsStore $knownHosts,
    ) {}

    /** @param non-empty-list<string> $arguments */
    public function execute(Node $node, array $arguments): CommandResult
    {
        $host = $node->wireguard_address;

        if (! is_string($host) || $host === '') {
            throw new ToolManagerException(
                step: 'ssh',
                message: 'The target node has no WireGuard address.',
            );
        }

        $result = $this->ssh->execute(
            new SshConnection(
                host: $host,
                user: 'orbit',
                port: 22,
                identityFile: $this->keys->privateKeyPath(),
                knownHostsFile: $this->knownHosts->path(),
            ),
            new RemoteCommand($arguments),
        );

        if ($result->truncated) {
            throw new ToolManagerException(
                step: 'ssh',
                message: 'The tool manager command output was truncated.',
                result: $result,
            );
        }

        return $result;
    }
}
