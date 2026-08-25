<?php

declare(strict_types=1);

use App\Domain\AppDev\AppDevCaddyManager;
use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\Nodes\NodeProvisioningException;
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
    $node = provisionable_node(role: RoleName::AppDev);

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
    $keys = test_keys();
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
    $caddy = new class implements AppDevCaddyManager {
        public bool $converged = false;

        public function converge(Node $node): void
        {
            $this->converged = true;
        }
    };
    $converger = new NativeNodeConverger(
        hostKeys: test_scanner(),
        knownHosts: $knownHosts,
        sshKeys: $keys,
        ssh: $ssh,
        bootstrapCommand: new NodeBootstrapCommandFactory($keys),
        wireGuard: $wireGuard,
        appDevCaddy: $caddy,
    );

    $converger->converge($node, 'SHA256:pinned');

    expect($node->refresh()->ssh_user)
        ->toBe('orbit')
        ->and($node->ssh_host_fingerprint)
        ->toBe('SHA256:pinned')
        ->and($knownHosts->key?->value)
        ->toBe('PUBLICKEY')
        ->and($wireGuard->converged)
        ->toBeTrue()
        ->and($caddy->converged)
        ->toBeTrue()
        ->and($ssh->calls)
        ->toHaveCount(3)
        ->and($ssh->calls[0]['connection']->user)
        ->toBe('root')
        ->and($ssh->calls[0]['command']->arguments)
        ->toContain(
            'acl',
            'attr',
            'caddy',
            'composer',
            'docker.io',
            'openssl',
            'php8.5-curl',
            'php8.5-fpm',
            'php8.5-intl',
            'php8.5-mbstring',
            'php8.5-xml',
            'php8.5-zip',
            'unzip',
        )
        ->and($ssh->calls[0]['command']->input)
        ->toContain(
            'app_dev=$2',
            'install -d -m 0700 -o orbit -g orbit /home/orbit',
            'install -d -m 0755 -o orbit -g orbit /home/orbit/apps /home/orbit/.orbit/worktrees',
            'setfacl -m u:caddy:--x /home/orbit /home/orbit/apps /home/orbit/.orbit /home/orbit/.orbit/worktrees',
        )
        ->and(mb_strpos(
            haystack: $ssh->calls[0]['command']->input ?? '',
            needle: 'install -d -m 0700 -o orbit -g orbit /home/orbit',
        ))
        ->toBeLessThan(mb_strpos(
            haystack: $ssh->calls[0]['command']->input ?? '',
            needle: 'setfacl -m u:caddy:--x /home/orbit',
        ))
        ->and($ssh->calls[1]['connection']->user)
        ->toBe('orbit')
        ->and($ssh->calls[1]['command']->arguments)
        ->toBe(['true'])
        ->and($ssh->calls[2]['connection']->host)
        ->toBe('10.44.0.2')
        ->and($ssh->calls[2]['command']->arguments)
        ->toBe(['true']);
});

it('requires an expected fingerprint before first-contact SSH', function (): void {
    $node = provisionable_node(role: RoleName::AppDev);
    $knownHostsWrites = [];
    $sshCalls = [];
    $converger = fingerprint_guard_converger($knownHostsWrites, $sshCalls);

    expect(fn () => $converger->converge($node))
        ->toThrow(function (NodeProvisioningException $exception): void {
            expect($exception->step)
                ->toBe('ssh-host-key')
                ->and($exception->errorCode)
                ->toBe('node.ssh_host_fingerprint_required');
        });

    expect($knownHostsWrites)
        ->toBeEmpty()
        ->and($sshCalls)
        ->toBeEmpty()
        ->and($node->refresh()->ssh_host_fingerprint)
        ->toBeNull();
});

it('rejects a first-contact fingerprint mismatch before pinning or SSH', function (): void {
    $node = provisionable_node(role: RoleName::AppDev);
    $knownHostsWrites = [];
    $sshCalls = [];
    $converger = fingerprint_guard_converger($knownHostsWrites, $sshCalls);

    expect(fn () => $converger->converge($node, 'SHA256:different'))
        ->toThrow(function (NodeProvisioningException $exception): void {
            expect($exception->step)
                ->toBe('ssh-host-key')
                ->and($exception->errorCode)
                ->toBe('node.ssh_host_key_mismatch');
        });

    expect($knownHostsWrites)
        ->toBeEmpty()
        ->and($sshCalls)
        ->toBeEmpty()
        ->and($node->refresh()->ssh_host_fingerprint)
        ->toBeNull();
});

it('preserves the stored pin when a known node host key changes', function (): void {
    $node = provisionable_node(role: RoleName::AppDev);
    $node->update(['ssh_host_fingerprint' => 'SHA256:original']);
    $knownHostsWrites = [];
    $sshCalls = [];
    $converger = fingerprint_guard_converger($knownHostsWrites, $sshCalls);

    expect(fn () => $converger->converge($node))
        ->toThrow(function (NodeProvisioningException $exception): void {
            expect($exception->step)
                ->toBe('ssh-host-key')
                ->and($exception->errorCode)
                ->toBe('node.ssh_host_key_changed');
        });

    expect($knownHostsWrites)
        ->toBeEmpty()
        ->and($sshCalls)
        ->toBeEmpty()
        ->and($node->refresh()->ssh_host_fingerprint)
        ->toBe('SHA256:original');
});

it('converges app-dev Caddy only after WireGuard SSH succeeds', function (): void {
    $node = provisionable_node(role: RoleName::AppDev);

    $events = [];
    $ssh = new class($events) implements SshExecutor {
        /** @param array<int, string> $events */
        public function __construct(
            private array &$events,
        ) {}

        public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
        {
            $this->events[] = "{$connection->user}@{$connection->host}:".implode(' ', $command->arguments);

            return new CommandResult(0, '', '', 10, false);
        }
    };
    $wireGuard = new class($events) implements WireGuardPeerConverger {
        /** @param array<int, string> $events */
        public function __construct(
            private array &$events,
        ) {}

        public function converge(Node $node, SshConnection $connection): void
        {
            $this->events[] = "wireguard:{$connection->user}@{$connection->host}";
        }
    };
    $caddy = new class($events) implements AppDevCaddyManager {
        /** @param array<int, string> $events */
        public function __construct(
            private array &$events,
        ) {}

        public function converge(Node $node): void
        {
            $this->events[] = "caddy:{$node->name}";
        }
    };
    $converger = new NativeNodeConverger(
        hostKeys: test_scanner(),
        knownHosts: test_known_hosts(),
        sshKeys: test_keys(),
        ssh: $ssh,
        bootstrapCommand: new NodeBootstrapCommandFactory(test_keys()),
        wireGuard: $wireGuard,
        appDevCaddy: $caddy,
    );

    $converger->converge($node, 'SHA256:pinned');

    expect($events)
        ->toHaveCount(5)
        ->and($events[0])
        ->toStartWith('root@94.237.40.75:bash -seu -- ')
        ->and($events[1])
        ->toBe('orbit@94.237.40.75:true')
        ->and($events[2])
        ->toBe('wireguard:orbit@94.237.40.75')
        ->and($events[3])
        ->toBe('orbit@10.44.0.2:true')
        ->and($events[4])
        ->toBe('caddy:app-dev');
});

it('does not converge app-dev Caddy for nodes without the app-dev role', function (): void {
    $node = provisionable_node(name: 'worker', role: RoleName::Gateway);

    $ssh = new class implements SshExecutor {
        public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
        {
            return new CommandResult(0, '', '', 10, false);
        }
    };
    $wireGuard = new class implements WireGuardPeerConverger {
        public function converge(Node $node, SshConnection $connection): void {}
    };
    $caddy = new class implements AppDevCaddyManager {
        public bool $converged = false;

        public function converge(Node $node): void
        {
            $this->converged = true;
        }
    };
    $converger = new NativeNodeConverger(
        hostKeys: test_scanner(),
        knownHosts: test_known_hosts(),
        sshKeys: test_keys(),
        ssh: $ssh,
        bootstrapCommand: new NodeBootstrapCommandFactory(test_keys()),
        wireGuard: $wireGuard,
        appDevCaddy: $caddy,
    );

    $converger->converge($node, 'SHA256:pinned');

    expect($caddy->converged)->toBeFalse();
});

it('converts app-dev Caddy failures into node provisioning failures', function (): void {
    $node = provisionable_node(role: RoleName::AppDev);

    $result = new CommandResult(1, '', 'broken caddy', 10, false);
    $previous = new RuntimeException('inner');
    $runtimeException = new RuntimeConvergenceException(
        step: 'caddy-config',
        errorCode: 'app-dev.caddy_config_failed',
        message: 'Caddy failed',
        previous: $previous,
        result: $result,
    );

    $ssh = new class implements SshExecutor {
        public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
        {
            return new CommandResult(0, '', '', 10, false);
        }
    };
    $wireGuard = new class implements WireGuardPeerConverger {
        public function converge(Node $node, SshConnection $connection): void {}
    };
    $caddy = new class($runtimeException) implements AppDevCaddyManager {
        public function __construct(
            private RuntimeConvergenceException $exception,
        ) {}

        public function converge(Node $node): void
        {
            throw $this->exception;
        }
    };
    $converger = new NativeNodeConverger(
        hostKeys: test_scanner(),
        knownHosts: test_known_hosts(),
        sshKeys: test_keys(),
        ssh: $ssh,
        bootstrapCommand: new NodeBootstrapCommandFactory(test_keys()),
        wireGuard: $wireGuard,
        appDevCaddy: $caddy,
    );

    expect(fn () => $converger->converge($node, 'SHA256:pinned'))
        ->toThrow(function (NodeProvisioningException $exception) use ($runtimeException, $previous, $result): void {
            expect($exception->step)
                ->toBe('caddy-config')
                ->and($exception->errorCode)
                ->toBe('app-dev.caddy_config_failed')
                ->and($exception->result)
                ->toBe($result)
                ->and($exception->getPrevious())
                ->toBe($runtimeException)
                ->and($runtimeException->getPrevious())
                ->toBe($previous);
        });
});

function provisionable_node(RoleName $role, string $name = 'app-dev'): Node
{
    $node = Node::query()->create([
        'name' => $name,
        'public_ssh_host' => '94.237.40.75',
        'public_ssh_port' => 22,
        'ssh_user' => 'root',
        'wireguard_address' => '10.44.0.2',
    ]);
    $node->roles()->create(['role' => $role]);

    return $node;
}

function test_scanner(): HostKeyScanner
{
    return new class implements HostKeyScanner {
        public function scan(string $host, int $port): HostKey
        {
            return new HostKey('ssh-ed25519', 'PUBLICKEY', 'SHA256:pinned');
        }
    };
}

function test_known_hosts(): KnownHostsStore
{
    return new class implements KnownHostsStore {
        public function path(): string
        {
            return '/home/orbit/.orbit/ssh/known_hosts';
        }

        public function put(string $host, int $port, HostKey $key): void {}
    };
}

function test_keys(): SshKeyProvider
{
    return new class implements SshKeyProvider {
        public function privateKeyPath(): string
        {
            return '/home/orbit/.orbit/ssh/id_ed25519';
        }

        public function publicKey(): string
        {
            return 'ssh-ed25519 GATEWAY';
        }
    };
}

/**
 * @param list<string> $knownHostsWrites
 * @param list<string> $sshCalls
 */
function fingerprint_guard_converger(array &$knownHostsWrites, array &$sshCalls): NativeNodeConverger
{
    $knownHosts = new class($knownHostsWrites) implements KnownHostsStore {
        /** @param list<string> $writes */
        public function __construct(
            private array &$writes,
        ) {}

        public function path(): string
        {
            return '/home/orbit/.orbit/ssh/known_hosts';
        }

        public function put(string $host, int $port, HostKey $key): void
        {
            $this->writes[] = $key->fingerprint;
        }
    };
    $ssh = new class($sshCalls) implements SshExecutor {
        /** @param list<string> $calls */
        public function __construct(
            private array &$calls,
        ) {}

        public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
        {
            $this->calls[] = $connection->host;

            return new CommandResult(0, '', '', 10, false);
        }
    };
    $wireGuard = new class implements WireGuardPeerConverger {
        public function converge(Node $node, SshConnection $connection): void {}
    };
    $caddy = new class implements AppDevCaddyManager {
        public function converge(Node $node): void {}
    };

    return new NativeNodeConverger(
        hostKeys: test_scanner(),
        knownHosts: $knownHosts,
        sshKeys: test_keys(),
        ssh: $ssh,
        bootstrapCommand: new NodeBootstrapCommandFactory(test_keys()),
        wireGuard: $wireGuard,
        appDevCaddy: $caddy,
    );
}
