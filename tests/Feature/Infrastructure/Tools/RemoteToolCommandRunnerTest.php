<?php

declare(strict_types=1);

use App\Domain\Tools\ToolManagerException;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Ssh\HostKey;
use App\Infrastructure\Ssh\KnownHostsStore;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshConnection;
use App\Infrastructure\Ssh\SshExecutor;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Infrastructure\Tools\RemoteToolCommandRunner;
use App\Models\Node;

describe(RemoteToolCommandRunner::class, function (): void {
    it('uses the node wireguard address and fixed argv execution', function (): void {
        $executor = new class implements SshExecutor
        {
            public ?SshConnection $connection = null;

            public ?RemoteCommand $command = null;

            public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
            {
                $this->connection = $connection;
                $this->command = $command;

                return new CommandResult(0, '', '', 12, false);
            }
        };
        $runner = new RemoteToolCommandRunner(
            ssh: $executor,
            keys: remote_tool_runner_keys(),
            knownHosts: remote_tool_runner_known_hosts(),
        );

        $result = $runner->execute(remote_tool_runner_node('10.8.0.7'), ['sudo', 'apt-get', 'update']);

        expect($result->exitCode)->toBe(0)
            ->and($executor->connection)
            ->toBeInstanceOf(SshConnection::class)
            ->and($executor->connection?->host)->toBe('10.8.0.7')
            ->and($executor->connection?->user)->toBe('orbit')
            ->and($executor->connection?->port)->toBe(22)
            ->and($executor->connection?->identityFile)->toBe('/tmp/orbit/id_ed25519')
            ->and($executor->connection?->knownHostsFile)->toBe('/tmp/orbit/known_hosts')
            ->and($executor->command?->arguments)->toBe(['sudo', 'apt-get', 'update'])
            ->and($executor->command?->input)->toBeNull()
            ->and($executor->command?->protectedInput)->toBeNull();
    });

    it('rejects nodes without a wireguard address', function (): void {
        $runner = new RemoteToolCommandRunner(
            ssh: new class implements SshExecutor
            {
                public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
                {
                    return new CommandResult(0, '', '', 1, false);
                }
            },
            keys: remote_tool_runner_keys(),
            knownHosts: remote_tool_runner_known_hosts(),
        );

        expect(fn () => $runner->execute(remote_tool_runner_node(null), ['sudo', 'apt-get', 'update']))
            ->toThrow(ToolManagerException::class, 'no WireGuard address');
    });

    it('rejects truncated remote output without exposing the raw buffers', function (): void {
        $stdoutSentinel = 'sentinel-stdout';
        $stderrSentinel = 'sentinel-stderr';
        $runner = new RemoteToolCommandRunner(
            ssh: new class($stdoutSentinel, $stderrSentinel) implements SshExecutor
            {
                public function __construct(
                    private readonly string $stdoutSentinel,
                    private readonly string $stderrSentinel,
                ) {}

                public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
                {
                    return new CommandResult(1, $this->stdoutSentinel, $this->stderrSentinel, 15, true);
                }
            },
            keys: remote_tool_runner_keys(),
            knownHosts: remote_tool_runner_known_hosts(),
        );

        expect(fn () => $runner->execute(remote_tool_runner_node('10.8.0.8'), ['sudo', 'apt-cache', 'policy']))
            ->toThrow(function (ToolManagerException $exception) use ($stdoutSentinel, $stderrSentinel): void {
                expect($exception->step)->toBe('ssh')
                    ->and($exception->result?->stdout)->toBeEmpty()
                    ->and($exception->result?->stderr)->toBeEmpty()
                    ->and($exception->getMessage())->not->toContain($stdoutSentinel, $stderrSentinel)
                    ->and(print_r($exception, return: true))->not->toContain($stdoutSentinel, $stderrSentinel);
            });
    });
});

function remote_tool_runner_node(?string $wireguardAddress): Node
{
    return new Node([
        'name' => 'tool-node',
        'status' => 'active',
        'platform' => 'linux',
        'public_ssh_host' => '127.0.0.1',
        'ssh_user' => 'orbit',
        'wireguard_address' => $wireguardAddress,
    ]);
}

function remote_tool_runner_keys(): SshKeyProvider
{
    return new class implements SshKeyProvider
    {
        public function privateKeyPath(): string
        {
            return '/tmp/orbit/id_ed25519';
        }

        public function publicKey(): string
        {
            return 'ssh-ed25519 AAAATEST orbit@test';
        }
    };
}

function remote_tool_runner_known_hosts(): KnownHostsStore
{
    return new class implements KnownHostsStore
    {
        public function path(): string
        {
            return '/tmp/orbit/known_hosts';
        }

        public function put(string $host, int $port, HostKey $key): void {}
    };
}
