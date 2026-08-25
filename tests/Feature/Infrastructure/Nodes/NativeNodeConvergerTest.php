<?php

declare(strict_types=1);

use App\Domain\Nodes\RoleName;
use App\Infrastructure\Nodes\NativeNodeConverger;
use App\Infrastructure\Nodes\NodeBootstrapCommandFactory;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Ssh\HostKey;
use App\Infrastructure\Ssh\HostKeyScanner;
use App\Infrastructure\Ssh\KnownHostsStore;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshConnection;
use App\Infrastructure\Ssh\SshExecutor;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Infrastructure\WireGuard\WireGuardPeerConverger;
use App\Models\Node;

it('pins the host and bootstraps verified orbit SSH access', function (): void {
    $node = Node::query()->create([
        'name' => 'app-dev',
        'public_ssh_host' => '94.237.40.75',
        'public_ssh_port' => 22,
        'ssh_user' => 'root',
        'wireguard_address' => '10.44.0.2',
    ]);
    $node->roles()->create(['role' => RoleName::AppDev]);

    $scanner = new class implements HostKeyScanner {
        public function scan(string $host, int $port): HostKey
        {
            return new HostKey('ssh-ed25519', 'PUBLICKEY', 'SHA256:pinned');
        }
    };
    $knownHosts = new class implements KnownHostsStore {
        public ?HostKey $key = null;

        public function path(): string
        {
            return '/home/orbit/.orbit/ssh/known_hosts';
        }

        public function put(string $host, int $port, HostKey $key): void
        {
            $this->key = $key;
        }
    };
    $keys = new class implements SshKeyProvider {
        public function privateKeyPath(): string
        {
            return '/home/orbit/.orbit/ssh/id_ed25519';
        }

        public function publicKey(): string
        {
            return 'ssh-ed25519 GATEWAY';
        }
    };
    $ssh = new class implements SshExecutor {
        /** @var list<array{connection: SshConnection, command: RemoteCommand}> */
        public array $calls = [];

        public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
        {
            $this->calls[] = ['connection' => $connection, 'command' => $command];

            return new CommandResult(0, '', '', 10, false);
        }
    };
    $wireGuard = new class implements WireGuardPeerConverger {
        public bool $converged = false;

        public function converge(Node $node, SshConnection $connection): void
        {
            $this->converged = true;
        }
    };
    $converger = new NativeNodeConverger(
        hostKeys: $scanner,
        knownHosts: $knownHosts,
        sshKeys: $keys,
        ssh: $ssh,
        bootstrapCommand: new NodeBootstrapCommandFactory($keys),
        wireGuard: $wireGuard,
    );

    $converger->converge($node);

    expect($node->refresh()->ssh_user)
        ->toBe('orbit')
        ->and($node->ssh_host_fingerprint)
        ->toBe('SHA256:pinned')
        ->and($knownHosts->key?->value)
        ->toBe('PUBLICKEY')
        ->and($wireGuard->converged)
        ->toBeTrue()
        ->and($ssh->calls)
        ->toHaveCount(3)
        ->and($ssh->calls[0]['connection']->user)
        ->toBe('root')
        ->and($ssh->calls[0]['command']->arguments)
        ->toContain(
            'caddy',
            'composer',
            'docker.io',
            'php8.5-curl',
            'php8.5-fpm',
            'php8.5-intl',
            'php8.5-mbstring',
            'php8.5-xml',
            'php8.5-zip',
            'unzip',
        )
        ->and($ssh->calls[1]['connection']->user)
        ->toBe('orbit')
        ->and($ssh->calls[1]['command']->arguments)
        ->toBe(['true'])
        ->and($ssh->calls[2]['connection']->host)
        ->toBe('10.44.0.2')
        ->and($ssh->calls[2]['command']->arguments)
        ->toBe(['true']);
});
