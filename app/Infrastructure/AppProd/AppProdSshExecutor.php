<?php

declare(strict_types=1);

namespace App\Infrastructure\AppProd;

use App\Domain\AppDev\RuntimeConvergenceException;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Ssh\KnownHostsStore;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshConnection;
use App\Infrastructure\Ssh\SshExecutor;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Models\Node;

final readonly class AppProdSshExecutor
{
    public function __construct(
        private SshExecutor $ssh,
        private SshKeyProvider $keys,
        private KnownHostsStore $knownHosts,
    ) {}

    public function execute(Node $node, RemoteCommand $command, string $step, string $errorCode): CommandResult
    {
        if (! is_string($node->wireguard_address) || $node->wireguard_address === '') {
            throw new RuntimeConvergenceException(
                step: $step,
                errorCode: 'app-prod.wireguard_address_missing',
                message: "Node [{$node->name}] has no WireGuard address.",
            );
        }

        $result = $this->ssh->execute(
            new SshConnection(
                host: $node->wireguard_address,
                user: 'orbit',
                port: 22,
                identityFile: $this->keys->privateKeyPath(),
                knownHostsFile: $this->knownHosts->path(),
            ),
            $command,
        );

        if (! $result->succeeded()) {
            throw new RuntimeConvergenceException(
                step: $step,
                errorCode: $errorCode,
                message: "App production step [{$step}] failed on node [{$node->name}].",
                result: $result,
            );
        }

        return $result;
    }
}
