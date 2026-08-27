<?php

declare(strict_types=1);

use App\Domain\Firewall\FirewallOperationException;
use App\Domain\Nodes\NodeProvisioningException;
use App\Domain\Nodes\NodeRoleFirewallManager;
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
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Str;
use Symfony\Component\Process\Process;

it('fails closed before SSH when no host adapter supports the node platform', function (): void {
    expect(interface_exists(NodeRoleFirewallManager::class))->toBeTrue();

    $node = base_provisionable_node();
    $node->update(['platform' => 'windows']);
    $scans = 0;
    $scanner = new class($scans) implements HostKeyScanner {
        public function __construct(
            private int &$scans,
        ) {}

        public function scan(string $host, int $port): HostKey
        {
            $this->scans++;

            return new HostKey('ssh-ed25519', 'PUBLICKEY', 'SHA256:pinned');
        }
    };
    $converger = base_node_converger(
        scanner: $scanner,
        ssh: new class implements SshExecutor {
            public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
            {
                throw new LogicException('SSH must not run for an unsupported platform.');
            }
        },
    );

    expect(fn () => $converger->converge($node, 'SHA256:pinned'))
        ->toThrow(function (NodeProvisioningException $exception): void {
            expect($exception->step)
                ->toBe('platform')
                ->and($exception->errorCode)
                ->toBe('node.platform_unsupported');
        });
    expect($scans)->toBe(0);
});

it('stops unsupported operating systems before the first bootstrap mutation', function (?string $release): void {
    $result = run_base_bootstrap_preflight($release);

    expect($result->isSuccessful())
        ->toBeFalse()
        ->and($result->getErrorOutput())
        ->toContain('Orbit requires Ubuntu 26.04 Resolute.')
        ->and($result->getOutput())
        ->not->toContain('mutation-reached');
})->with([
    'missing release file' => null,
    'Ubuntu Noble' => "ID=ubuntu\nVERSION_CODENAME=noble\n",
    'Debian' => "ID=debian\nVERSION_CODENAME=resolute\n",
    'malformed codename' => "ID=ubuntu\nVERSION_CODENAME='resolute extra'\n",
]);

it('keeps the base bootstrap role-neutral with one fixed shared package list', function (): void {
    $command = base_bootstrap_command();
    $script = $command->input ?? '';

    expect($command->arguments)
        ->toBe([
            'bash',
            '-seu',
            '--',
            'ssh-ed25519 GATEWAY',
            'ca-certificates',
            'curl',
            'gnupg',
            'openssh-client',
            'sudo',
            'ufw',
            'wireguard',
        ])
        ->and($script)
        ->toContain(
            'Orbit requires Ubuntu 26.04 Resolute.',
            'useradd --create-home --shell /bin/bash orbit',
            'install -d -m 0700 -o orbit -g orbit /home/orbit',
            'orbit ALL=(ALL) NOPASSWD:ALL',
        )
        ->not->toContain(
            '/home/orbit/apps',
            '/home/orbit/.orbit/worktrees',
            'setfacl',
            '/opt/orbit/vite-plus',
            '/opt/orbit/bun',
            'https://vite.plus',
            'https://bun.com/install',
            '/usr/local/bin/node',
            'caddy',
            'dnsmasq',
            'docker.io',
            'openssl',
        );
});

it('pins the host and converges only base node identity and connectivity', function (): void {
    expect(interface_exists(NodeRoleFirewallManager::class))->toBeTrue();

    $node = base_provisionable_node();
    $knownHosts = new class implements KnownHostsStore {
        /** @var list<string> */
        public array $hosts = [];

        public function path(): string
        {
            return '/tmp/orbit-known-hosts';
        }

        public function put(string $host, int $port, HostKey $key): void
        {
            $this->hosts[] = "{$host}:{$port}:{$key->fingerprint}";
        }
    };
    $ssh = new BaseNodeSshExecutor;
    $baseNodes = [];
    $firewall = base_firewall_spy($baseNodes);
    $wireGuard = new class implements WireGuardPeerConverger {
        public bool $converged = false;

        public function converge(Node $node, SshConnection $connection): void
        {
            $this->converged = true;
        }
    };
    $converger = new NativeNodeConverger(
        hostKeys: base_test_scanner(),
        knownHosts: $knownHosts,
        sshKeys: base_test_keys(),
        ssh: $ssh,
        bootstrapCommand: new NodeBootstrapCommandFactory(base_test_keys()),
        wireGuard: $wireGuard,
        firewall: $firewall,
    );

    $converger->converge($node, 'SHA256:pinned');

    expect($node->refresh()->ssh_user)
        ->toBe('orbit')
        ->and($node->ssh_host_fingerprint)
        ->toBe('SHA256:pinned')
        ->and($knownHosts->hosts)
        ->toBe([
            '192.0.2.10:22:SHA256:pinned',
            '10.44.0.2:22:SHA256:pinned',
        ])
        ->and($baseNodes)
        ->toBe([$node->id])
        ->and($wireGuard->converged)
        ->toBeTrue()
        ->and($ssh->calls)
        ->toHaveCount(3)
        ->and($ssh->calls[0]['connection']->user)
        ->toBe('root')
        ->and($ssh->calls[1]['command']->arguments)
        ->toBe(['true'])
        ->and($ssh->calls[2]['connection']->host)
        ->toBe('10.44.0.2')
        ->and($ssh->calls[2]['command']->arguments)
        ->toBe(['true']);
});

it('uses passwordless sudo for the same fixed base command when reconnecting as orbit', function (): void {
    expect(interface_exists(NodeRoleFirewallManager::class))->toBeTrue();

    $node = base_provisionable_node();
    $node->update(['ssh_user' => 'orbit', 'ssh_host_fingerprint' => 'SHA256:pinned']);
    $ssh = new BaseNodeSshExecutor;
    $factory = new NodeBootstrapCommandFactory(base_test_keys());
    $expected = $factory->make($node);
    $converger = new NativeNodeConverger(
        hostKeys: base_test_scanner(),
        knownHosts: base_test_known_hosts(),
        sshKeys: base_test_keys(),
        ssh: $ssh,
        bootstrapCommand: $factory,
        wireGuard: new class implements WireGuardPeerConverger {
            public function converge(Node $node, SshConnection $connection): void {}
        },
        firewall: base_firewall_spy(),
    );

    $converger->converge($node);

    expect($ssh->calls[0]['command']->arguments)
        ->toBe(['sudo', '-n', '--', ...$expected->arguments])
        ->and($ssh->calls[0]['command']->input)
        ->toBe($expected->input);
});

it('reports a bounded base bootstrap failure before later convergence', function (): void {
    expect(interface_exists(NodeRoleFirewallManager::class))->toBeTrue();

    $node = base_provisionable_node();
    $failure = new CommandResult(1, '', 'sudo failed', 10, false);
    $ssh = new class($failure) implements SshExecutor {
        public function __construct(
            private CommandResult $failure,
        ) {}

        public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
        {
            return $this->failure;
        }
    };
    $converger = base_node_converger($ssh);

    expect(fn () => $converger->converge($node, 'SHA256:pinned'))
        ->toThrow(function (NodeProvisioningException $exception) use ($failure): void {
            expect($exception->step)
                ->toBe('base-host')
                ->and($exception->errorCode)
                ->toBe('node.bootstrap_failed')
                ->and($exception->result)
                ->toBe($failure);
        });
});

it('translates base firewall failures to node provisioning failures', function (): void {
    expect(interface_exists(NodeRoleFirewallManager::class))->toBeTrue();

    $node = base_provisionable_node();
    $result = new CommandResult(1, '', 'ufw failed', 10, false);
    $firewall = new class($result) implements NodeRoleFirewallManager {
        public function __construct(
            private CommandResult $result,
        ) {}

        public function convergeBase(Node $node): void
        {
            throw new FirewallOperationException(
                step: 'host-firewall',
                errorCode: 'node.firewall_convergence_failed',
                message: 'Could not converge UFW.',
                result: $this->result,
            );
        }

        public function converge(Node $node, RoleName $role): void {}

        public function remove(Node $node, RoleName $role): void {}
    };
    $converger = base_node_converger(new BaseNodeSshExecutor, firewall: $firewall);

    expect(fn () => $converger->converge($node, 'SHA256:pinned'))
        ->toThrow(function (NodeProvisioningException $exception) use ($result): void {
            expect($exception->step)
                ->toBe('host-firewall')
                ->and($exception->errorCode)
                ->toBe('node.firewall_convergence_failed')
                ->and($exception->result)
                ->toBe($result);
        });
});

it('guards first-contact and stored SSH fingerprints before remote effects', function (
    ?string $stored,
    ?string $expected,
    string $observed,
    string $code,
): void {
    expect(interface_exists(NodeRoleFirewallManager::class))->toBeTrue();

    $node = base_provisionable_node();
    $node->update(['ssh_host_fingerprint' => $stored]);
    $calls = 0;
    $ssh = new class($calls) implements SshExecutor {
        public function __construct(
            private int &$calls,
        ) {}

        public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
        {
            $this->calls++;

            return new CommandResult(0, '', '', 1, false);
        }
    };
    $scanner = new class($observed) implements HostKeyScanner {
        public function __construct(
            private string $observed,
        ) {}

        public function scan(string $host, int $port): HostKey
        {
            return new HostKey('ssh-ed25519', 'PUBLICKEY', $this->observed);
        }
    };
    $converger = base_node_converger($ssh, scanner: $scanner);

    expect(fn () => $converger->converge($node, $expected))
        ->toThrow(function (NodeProvisioningException $exception) use ($code): void {
            expect($exception->step)
                ->toBe('ssh-host-key')
                ->and($exception->errorCode)
                ->toBe($code);
        });
    expect($calls)->toBe(0);
})->with([
    'expected fingerprint is required' => [null, null, 'SHA256:pinned', 'node.ssh_host_fingerprint_required'],
    'first-contact mismatch' => [null, 'SHA256:expected', 'SHA256:other', 'node.ssh_host_key_mismatch'],
    'stored key changed' => ['SHA256:stored', null, 'SHA256:other', 'node.ssh_host_key_changed'],
]);

function base_provisionable_node(): Node
{
    $node = Node::query()->create([
        'name' => 'base-node',
        'platform' => 'linux',
        'public_ssh_host' => '192.0.2.10',
        'public_ssh_port' => 22,
        'ssh_user' => 'root',
        'wireguard_address' => '10.44.0.2',
    ]);
    $node->roles()->create(['role' => RoleName::AppDev]);

    return $node;
}

function base_test_scanner(): HostKeyScanner
{
    return new class implements HostKeyScanner {
        public function scan(string $host, int $port): HostKey
        {
            return new HostKey('ssh-ed25519', 'PUBLICKEY', 'SHA256:pinned');
        }
    };
}

function base_test_known_hosts(): KnownHostsStore
{
    return new class implements KnownHostsStore {
        public function path(): string
        {
            return '/tmp/orbit-known-hosts';
        }

        public function put(string $host, int $port, HostKey $key): void {}
    };
}

function base_test_keys(): SshKeyProvider
{
    return new class implements SshKeyProvider {
        public function privateKeyPath(): string
        {
            return '/tmp/orbit-key';
        }

        public function publicKey(): string
        {
            return 'ssh-ed25519 GATEWAY';
        }
    };
}

function base_bootstrap_command(): RemoteCommand
{
    return new NodeBootstrapCommandFactory(base_test_keys())->make(new Node);
}

function run_base_bootstrap_preflight(?string $release): Process
{
    $filesystem = new Filesystem;
    $directory = sys_get_temp_dir().'/orbit-node-bootstrap-'.Str::random(16);
    $releasePath = "{$directory}/os-release";
    $filesystem->makeDirectory($directory, 0o700);

    if ($release !== null) {
        $filesystem->put($releasePath, $release);
    }

    $script = base_bootstrap_command()->input ?? '';
    $preMutation = strstr(haystack: $script, needle: 'export DEBIAN_FRONTEND=noninteractive', before_needle: true);
    $harness =
        str_replace('/etc/os-release', $releasePath, is_string($preMutation) ? $preMutation : $script)
        ."printf 'mutation-reached\\n'\n";
    $process = new Process(['bash', '-seu', '--', 'ssh-ed25519 TEST']);
    $process->setInput($harness);
    $process->run();
    $filesystem->deleteDirectory($directory);

    return $process;
}

function base_node_converger(
    SshExecutor $ssh,
    ?HostKeyScanner $scanner = null,
    ?NodeRoleFirewallManager $firewall = null,
): NativeNodeConverger {
    return new NativeNodeConverger(
        hostKeys: $scanner ?? base_test_scanner(),
        knownHosts: base_test_known_hosts(),
        sshKeys: base_test_keys(),
        ssh: $ssh,
        bootstrapCommand: new NodeBootstrapCommandFactory(base_test_keys()),
        wireGuard: new class implements WireGuardPeerConverger {
            public function converge(Node $node, SshConnection $connection): void {}
        },
        firewall: $firewall ?? base_firewall_spy(),
    );
}

/** @mago-expect lint:file-name The fake stays with its base convergence tests. */
final class BaseNodeSshExecutor implements SshExecutor
{
    /** @var list<array{connection: SshConnection, command: RemoteCommand}> */
    public array $calls = [];

    public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
    {
        $this->calls[] = ['connection' => $connection, 'command' => $command];

        return new CommandResult(0, '', '', 1, false);
    }
}

/** @param list<int>|null $baseNodes */
function base_firewall_spy(?array &$baseNodes = null): NodeRoleFirewallManager
{
    $firewall = Mockery::mock(NodeRoleFirewallManager::class);
    $firewall
        ->shouldReceive('convergeBase')
        ->andReturnUsing(static function (Node $node) use (&$baseNodes): void {
            if (is_array($baseNodes)) {
                $baseNodes[] = $node->id;
            }
        });

    return $firewall;
}
