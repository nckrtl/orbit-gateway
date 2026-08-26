<?php

declare(strict_types=1);

namespace App\Infrastructure\WireGuard;

use App\Domain\Nodes\NodeProvisioningException;
use App\Domain\WireGuard\GatewayPeerProjectionManager;
use App\Infrastructure\Files\ProtectedFileWriter;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Processes\ProcessRunner;
use App\Models\Node;

/** @mago-expect lint:too-many-methods Peer publication keeps one locked host transaction in one adapter. */
final readonly class NativeGatewayPeerProjectionManager implements GatewayPeerProjectionManager
{
    private const string GENERATED_CONFIG_PATH = '/generated/wireguard/orbit.conf';

    private const string CANDIDATE_CONFIG_PATH = '/etc/wireguard/orbit-candidate.conf';

    private const string LIVE_CONFIG_PATH = '/etc/wireguard/orbit.conf';

    private const string BACKUP_CONFIG_PATH = '/etc/wireguard/.orbit.conf.rollback';

    private const string LOCK_PATH = '/locks/wireguard-server.lock';

    public function __construct(
        private VpnConfigurationRepository $configuration,
        private WireGuardServerConfigRenderer $serverRenderer,
        private ProtectedFileWriter $files,
        private ProcessRunner $processes,
        private string $orbitHome,
    ) {}

    public function converge(Node $node): void
    {
        $this->project($node, null);
    }

    public function remove(Node $node): void
    {
        $this->project($node, $node->id);
    }

    public function restore(Node $node): void
    {
        $this->project($node, null);
    }

    private function project(Node $context, ?int $excludedNodeId): void
    {
        $this->withLock(function () use ($context, $excludedNodeId): void {
            $vpn = $this->configuration->forPeer($context);
            $nodes = Node::query()->whereNotNull('wireguard_public_key');

            if ($excludedNodeId !== null) {
                $nodes->whereKeyNot($excludedNodeId);
            }

            $serverConfig = $this->serverRenderer->render($vpn, $nodes->get());
            $generatedPath = $this->path(self::GENERATED_CONFIG_PATH);
            $this->files->put($generatedPath, $serverConfig);
            $this->install($generatedPath);
            $this->activate();
        });
    }

    private function withLock(callable $operation): void
    {
        $lockPath = $this->path(self::LOCK_PATH);
        $directory = dirname($lockPath);

        if (
            ! is_dir($directory)
            && ! mkdir(directory: $directory, permissions: 0o700, recursive: true)
            && ! is_dir($directory)
        ) {
            throw $this->failure('wireguard-server-lock', 'vpn.server_lock_failed');
        }

        chmod(filename: $directory, permissions: 0o700);
        $lock = fopen(filename: $lockPath, mode: 'c+');

        if ($lock === false) {
            throw $this->failure('wireguard-server-lock', 'vpn.server_lock_failed');
        }

        try {
            if (! flock($lock, LOCK_EX)) {
                throw $this->failure('wireguard-server-lock', 'vpn.server_lock_failed');
            }

            $operation();
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private function install(string $generatedPath): void
    {
        $backupCreated = false;

        try {
            $this->run(
                'wireguard-server-install',
                'vpn.server_config_install_failed',
                [
                    'sudo',
                    'install',
                    '-D',
                    '-o',
                    'root',
                    '-g',
                    'root',
                    '-m',
                    '0600',
                    '--',
                    $generatedPath,
                    self::CANDIDATE_CONFIG_PATH,
                ],
            );
            $this->run(
                'wireguard-server-validate',
                'vpn.server_config_invalid',
                ['sudo', 'wg-quick', 'strip', self::CANDIDATE_CONFIG_PATH],
            );
            $this->backup();
            $backupCreated = true;
            $this->run(
                'wireguard-server-install',
                'vpn.server_config_install_failed',
                ['sudo', 'mv', '-f', '--', self::CANDIDATE_CONFIG_PATH, self::LIVE_CONFIG_PATH],
            );
        } catch (NodeProvisioningException $exception) {
            $this->cleanup(
                $backupCreated
                    ? [self::CANDIDATE_CONFIG_PATH, self::BACKUP_CONFIG_PATH]
                    : [self::CANDIDATE_CONFIG_PATH],
            );

            throw $exception;
        }
    }

    private function backup(): void
    {
        $this->run(
            step: 'wireguard-server-install',
            errorCode: 'vpn.server_config_install_failed',
            arguments: ['sudo', 'bash', '-seu'],
            input: <<<'BASH'
                live=/etc/wireguard/orbit.conf
                backup=/etc/wireguard/.orbit.conf.rollback
                rm -f -- "$backup"
                if [ -f "$live" ]; then
                    cp --preserve=mode,ownership -- "$live" "$backup"
                fi
                BASH,
        );
    }

    private function activate(): void
    {
        $this->run(
            step: 'wireguard-server-restart',
            errorCode: 'vpn.server_start_failed',
            arguments: ['sudo', 'bash', '-seu'],
            input: <<<'BASH'
                live=/etc/wireguard/orbit.conf
                backup=/etc/wireguard/.orbit.conf.rollback
                restore_previous() {
                    if [ -f "$backup" ]; then
                        mv -fT -- "$backup" "$live"
                        systemctl restart wg-quick@orbit || true
                    else
                        rm -f -- "$live"
                        systemctl stop wg-quick@orbit || true
                    fi
                }
                if ! systemctl enable wg-quick@orbit; then
                    restore_previous
                    exit 1
                fi
                if ! systemctl restart wg-quick@orbit; then
                    restore_previous
                    exit 1
                fi
                rm -f -- "$backup"
                BASH,
        );
    }

    /** @param non-empty-list<string> $arguments */
    private function run(string $step, string $errorCode, array $arguments, ?string $input = null): void
    {
        $result = $this->processes->run(new ProcessInvocation($arguments, input: $input));

        if (! $result->succeeded()) {
            throw $this->failure($step, $errorCode, $result);
        }
    }

    /** @param non-empty-list<string> $paths */
    private function cleanup(array $paths): void
    {
        $this->processes->run(new ProcessInvocation(['sudo', 'rm', '-f', '--', ...$paths]));
    }

    private function failure(
        string $step,
        string $errorCode,
        ?CommandResult $result = null,
    ): NodeProvisioningException {
        return new NodeProvisioningException(
            step: $step,
            errorCode: $errorCode,
            message: 'Could not converge the gateway WireGuard service.',
            result: $result,
        );
    }

    private function path(string $suffix): string
    {
        return rtrim(string: $this->orbitHome, characters: '/').$suffix;
    }
}
