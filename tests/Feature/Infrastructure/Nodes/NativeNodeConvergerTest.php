<?php

declare(strict_types=1);

use App\Domain\AppDev\AppDevCaddyManager;
use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\Nodes\NodeProvisioningException;
use App\Domain\Nodes\RoleName;
use App\Infrastructure\Firewall\UfwStoredRuleProbe;
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
use Tests\Support\NodeExecutingInactiveUfwSshExecutor;

it('fails closed before SSH when no host adapter supports the node platform', function (): void {
    $node = provisionable_node(role: RoleName::AppDev);
    $node->update(['platform' => 'darwin']);
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
    $converger = new NativeNodeConverger(
        hostKeys: $scanner,
        knownHosts: test_known_hosts(),
        sshKeys: test_keys(),
        ssh: new class implements SshExecutor {
            public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
            {
                throw new LogicException('SSH must not run for an unsupported platform.');
            }
        },
        bootstrapCommand: new NodeBootstrapCommandFactory(test_keys()),
        wireGuard: new class implements WireGuardPeerConverger {
            public function converge(Node $node, SshConnection $connection): void {}
        },
        appDevCaddy: new class implements AppDevCaddyManager {
            public function converge(Node $node): void {}
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

            return node_success_result($command);
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
        ->toHaveCount(5)
        ->and($ssh->calls[0]['connection']->user)
        ->toBe('root')
        ->and(array_slice(array: $ssh->calls[0]['command']->arguments, offset: 0, length: 6))
        ->toBe([
            'bash',
            '-seu',
            '--',
            'ssh-ed25519 GATEWAY',
            '1',
            'ca-certificates',
        ])
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
        ->toBe('94.237.40.75')
        ->and($ssh->calls[2]['command']->arguments)
        ->toBe(['sudo', 'ufw', 'status', 'numbered'])
        ->and($ssh->calls[3]['command']->arguments)
        ->toBe(['sudo', 'ufw', 'status', 'numbered'])
        ->and($ssh->calls[4]['connection']->host)
        ->toBe('10.44.0.2')
        ->and($ssh->calls[4]['command']->arguments)
        ->toBe(['true']);
});

it('uses passwordless sudo for the fixed bootstrap command when reconnecting as orbit', function (): void {
    $node = provisionable_node(role: RoleName::AppProd, name: 'app-prod');
    $node->update([
        'ssh_user' => 'orbit',
        'ssh_host_fingerprint' => 'SHA256:pinned',
    ]);
    $keys = test_keys();
    $bootstrapCommand = new NodeBootstrapCommandFactory($keys);
    $expectedBootstrap = $bootstrapCommand->make($node->load('roles'));
    $ssh = new class implements SshExecutor {
        /** @var list<array{connection: SshConnection, command: RemoteCommand}> */
        public array $calls = [];

        public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
        {
            $this->calls[] = ['connection' => $connection, 'command' => $command];

            return node_success_result($command);
        }
    };
    $converger = new NativeNodeConverger(
        hostKeys: test_scanner(),
        knownHosts: test_known_hosts(),
        sshKeys: $keys,
        ssh: $ssh,
        bootstrapCommand: $bootstrapCommand,
        wireGuard: new class implements WireGuardPeerConverger {
            public function converge(Node $node, SshConnection $connection): void {}
        },
        appDevCaddy: new class implements AppDevCaddyManager {
            public function converge(Node $node): void {}
        },
    );

    $converger->converge($node);

    expect($ssh->calls[0]['connection']->user)
        ->toBe('orbit')
        ->and($ssh->calls[0]['command']->arguments)
        ->toBe(['sudo', '-n', '--', ...$expectedBootstrap->arguments])
        ->and($ssh->calls[0]['command']->input)
        ->toBe($expectedBootstrap->input)
        ->and($ssh->calls[0]['command']->protectedInput)
        ->toBeNull()
        ->and($ssh->calls[1]['command']->arguments)
        ->toBe(['true']);
});

it('reports a bounded bootstrap failure when passwordless sudo reconvergence fails', function (): void {
    $node = provisionable_node(role: RoleName::AppProd, name: 'app-prod');
    $node->update([
        'ssh_user' => 'orbit',
        'ssh_host_fingerprint' => 'SHA256:pinned',
    ]);
    $keys = test_keys();
    $bootstrapCommand = new NodeBootstrapCommandFactory($keys);
    $expectedBootstrap = $bootstrapCommand->make($node->load('roles'));
    $failure = new CommandResult(1, '', 'sudo: a password is required', 10, false);
    $ssh = new class($failure) implements SshExecutor {
        /** @var list<array{connection: SshConnection, command: RemoteCommand}> */
        public array $calls = [];

        public function __construct(
            private CommandResult $failure,
        ) {}

        public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
        {
            $this->calls[] = ['connection' => $connection, 'command' => $command];

            return $this->failure;
        }
    };
    $converger = new NativeNodeConverger(
        hostKeys: test_scanner(),
        knownHosts: test_known_hosts(),
        sshKeys: $keys,
        ssh: $ssh,
        bootstrapCommand: $bootstrapCommand,
        wireGuard: new class implements WireGuardPeerConverger {
            public function converge(Node $node, SshConnection $connection): void
            {
                throw new LogicException('WireGuard must not converge after bootstrap failure.');
            }
        },
        appDevCaddy: new class implements AppDevCaddyManager {
            public function converge(Node $node): void
            {
                throw new LogicException('Caddy must not converge after bootstrap failure.');
            }
        },
    );

    expect(fn () => $converger->converge($node))
        ->toThrow(function (NodeProvisioningException $exception) use ($failure): void {
            expect($exception->step)
                ->toBe('base-host')
                ->and($exception->errorCode)
                ->toBe('node.bootstrap_failed')
                ->and($exception->getMessage())
                ->toBe('Could not bootstrap node [app-prod].')
                ->and($exception->result)
                ->toBe($failure);
        });

    expect($ssh->calls)
        ->toHaveCount(1)
        ->and($ssh->calls[0]['connection']->user)
        ->toBe('orbit')
        ->and($ssh->calls[0]['command']->arguments)
        ->toBe(['sudo', '-n', '--', ...$expectedBootstrap->arguments])
        ->and($ssh->calls[0]['command']->input)
        ->toBe($expectedBootstrap->input);
});

it('preserves verified public SSH before enabling only required UFW role rules', function (): void {
    $node = provisionable_node(role: RoleName::AppDev);
    $ssh = new NodeInactiveUfwSshExecutor;
    $converger = new NativeNodeConverger(
        hostKeys: test_scanner(),
        knownHosts: test_known_hosts(),
        sshKeys: test_keys(),
        ssh: $ssh,
        bootstrapCommand: new NodeBootstrapCommandFactory(test_keys()),
        wireGuard: new class implements WireGuardPeerConverger {
            public function converge(Node $node, SshConnection $connection): void {}
        },
        appDevCaddy: new class implements AppDevCaddyManager {
            public function converge(Node $node): void {}
        },
    );

    $converger->converge($node, 'SHA256:pinned');

    $arguments = collect($ssh->calls)
        ->map(static fn (array $call): array => $call['command']->arguments)
        ->all();

    expect($ssh->calls[1]['command']->arguments)
        ->toBe(['true'])
        ->and($ssh->calls[1]['connection']->host)
        ->toBe('94.237.40.75')
        ->and(array_slice(array: $arguments, offset: 2, length: 9))
        ->toBe([
            ['sudo', 'ufw', 'status', 'numbered'],
            $arguments[3],
            [
                'sudo',
                'ufw',
                'allow',
                'in',
                'proto',
                'tcp',
                'to',
                'any',
                'port',
                '22',
                'comment',
                'orbit:public-ssh-recovery',
            ],
            $arguments[5],
            ['sudo', 'ufw', '--force', 'enable'],
            ['sudo', 'ufw', 'status', 'numbered'],
            [
                'sudo',
                'ufw',
                'allow',
                'in',
                'on',
                'orbit',
                'proto',
                'tcp',
                'to',
                '10.44.0.2',
                'port',
                '80',
                'comment',
                'orbit:app-dev-http',
            ],
            [
                'sudo',
                'ufw',
                'allow',
                'in',
                'on',
                'orbit',
                'proto',
                'tcp',
                'to',
                '10.44.0.2',
                'port',
                '443',
                'comment',
                'orbit:app-dev-https',
            ],
            ['sudo', 'ufw', 'status', 'numbered'],
        ])
        ->and(array_slice(array: $arguments[3], offset: 0, length: 2))
        ->toBe(['sudo', 'awk'])
        ->and($arguments[3])
        ->toContain('/etc/ufw/user.rules', '/etc/ufw/user6.rules')
        ->and($arguments[5])
        ->toBe($arguments[3])
        ->and($arguments)
        ->not->toContain(
            ['sudo', 'ufw', 'reset'],
            ['sudo', 'ufw', 'delete'],
        );
});

it('refuses to enable inactive node UFW when the stored recovery rule is missing', function (): void {
    $node = provisionable_node(role: RoleName::AppDev);
    $ssh = new NodeInactiveUfwSshExecutor(failStoredRecovery: true);
    $converger = new NativeNodeConverger(
        hostKeys: test_scanner(),
        knownHosts: test_known_hosts(),
        sshKeys: test_keys(),
        ssh: $ssh,
        bootstrapCommand: new NodeBootstrapCommandFactory(test_keys()),
        wireGuard: new class implements WireGuardPeerConverger {
            public function converge(Node $node, SshConnection $connection): void {}
        },
        appDevCaddy: new class implements AppDevCaddyManager {
            public function converge(Node $node): void {}
        },
    );

    expect(fn () => $converger->converge($node, 'SHA256:pinned'))
        ->toThrow(function (NodeProvisioningException $exception): void {
            expect($exception->step)
                ->toBe('host-firewall')
                ->and($exception->errorCode)
                ->toBe('node.firewall_convergence_failed');
        });
    $arguments = collect($ssh->calls)
        ->map(static fn (array $call): array => $call['command']->arguments);

    expect($arguments->contains(['sudo', 'ufw', '--force', 'enable']))
        ->toBeFalse()
        ->and($arguments->contains(
            static fn (array $command): bool => in_array(
                needle: 'orbit:app-dev-http',
                haystack: $command,
                strict: true,
            ),
        ))
        ->toBeFalse();
});

it('fails closed before mutating inactive UFW when a stored app-dev comment has a broader shape', function (): void {
    $node = provisionable_node(role: RoleName::AppDev);
    $ssh = new NodeInactiveUfwSshExecutor(storedRuleDrift: true);
    $converger = new NativeNodeConverger(
        hostKeys: test_scanner(),
        knownHosts: test_known_hosts(),
        sshKeys: test_keys(),
        ssh: $ssh,
        bootstrapCommand: new NodeBootstrapCommandFactory(test_keys()),
        wireGuard: new class implements WireGuardPeerConverger {
            public function converge(Node $node, SshConnection $connection): void {}
        },
        appDevCaddy: new class implements AppDevCaddyManager {
            public function converge(Node $node): void {}
        },
    );

    expect(fn () => $converger->converge($node, 'SHA256:pinned'))
        ->toThrow(function (NodeProvisioningException $exception): void {
            expect($exception->step)
                ->toBe('host-firewall')
                ->and($exception->errorCode)
                ->toBe('node.firewall_convergence_failed');
        });
    $mutations = collect($ssh->calls)
        ->map(static fn (array $call): array => $call['command']->arguments)
        ->filter(
            static fn (array $arguments): bool => (
                array_slice(array: $arguments, offset: 0, length: 2) === ['sudo', 'ufw']
                && array_slice(array: $arguments, offset: 0, length: 3) !== ['sudo', 'ufw', 'status']
            ),
        );

    expect($mutations)->toBeEmpty();
});

it('rejects a stored recovery rule restricted to the WireGuard interface before enabling UFW', function (): void {
    $node = provisionable_node(role: RoleName::AppDev);
    $ssh = new NodeInactiveUfwSshExecutor(storedRecoveryWrongShape: true);
    $converger = new NativeNodeConverger(
        hostKeys: test_scanner(),
        knownHosts: test_known_hosts(),
        sshKeys: test_keys(),
        ssh: $ssh,
        bootstrapCommand: new NodeBootstrapCommandFactory(test_keys()),
        wireGuard: new class implements WireGuardPeerConverger {
            public function converge(Node $node, SshConnection $connection): void {}
        },
        appDevCaddy: new class implements AppDevCaddyManager {
            public function converge(Node $node): void {}
        },
    );

    expect(fn () => $converger->converge($node, 'SHA256:pinned'))
        ->toThrow(function (NodeProvisioningException $exception): void {
            expect($exception->step)
                ->toBe('host-firewall')
                ->and($exception->errorCode)
                ->toBe('node.firewall_convergence_failed');
        });
    $arguments = collect($ssh->calls)
        ->map(static fn (array $call): array => $call['command']->arguments);
    $mutations = $arguments->filter(
        static fn (array $command): bool => (
            array_slice(array: $command, offset: 0, length: 2) === ['sudo', 'ufw']
            && array_slice(array: $command, offset: 0, length: 3) !== ['sudo', 'ufw', 'status']
        ),
    );

    expect($mutations)->toBeEmpty();
});

it('executes stored rule inspection and rejects inactive recovery ownership drift before mutation', function (
    array $ipv4Rules,
    array $ipv6Rules,
): void {
    $directory = sys_get_temp_dir().'/orbit-node-stored-ufw-'.Str::uuid();
    mkdir(directory: $directory, permissions: 0o700);
    $ipv4Path = $directory.'/user.rules';
    $ipv6Path = $directory.'/user6.rules';
    file_put_contents($ipv4Path, implode("\n", $ipv4Rules)."\n");
    file_put_contents($ipv6Path, implode("\n", $ipv6Rules)."\n");
    $node = provisionable_node(role: RoleName::AppDev);
    $ssh = new NodeExecutingInactiveUfwSshExecutor($ipv4Path, $ipv6Path);
    $converger = new NativeNodeConverger(
        hostKeys: test_scanner(),
        knownHosts: test_known_hosts(),
        sshKeys: test_keys(),
        ssh: $ssh,
        bootstrapCommand: new NodeBootstrapCommandFactory(test_keys()),
        wireGuard: new class implements WireGuardPeerConverger {
            public function converge(Node $node, SshConnection $connection): void {}
        },
        appDevCaddy: new class implements AppDevCaddyManager {
            public function converge(Node $node): void {}
        },
    );

    try {
        expect(fn () => $converger->converge($node, 'SHA256:pinned'))
            ->toThrow(function (NodeProvisioningException $exception): void {
                expect($exception->step)
                    ->toBe('host-firewall')
                    ->and($exception->errorCode)
                    ->toBe('node.firewall_convergence_failed');
            });

        $arguments = collect($ssh->calls)
            ->map(static fn (array $call): array => $call['command']->arguments);
        $mutations = $arguments->filter(
            static fn (array $command): bool => (
                array_slice(array: $command, offset: 0, length: 2) === ['sudo', 'ufw']
                && array_slice(array: $command, offset: 0, length: 3) !== ['sudo', 'ufw', 'status']
            ),
        );

        expect($arguments->contains(UfwStoredRuleProbe::arguments()))
            ->toBeTrue()
            ->and($ssh->storedOutput)
            ->toContain(
                "__orbit_ufw_tuple:v4:{$ipv4Rules[0]}",
                "__orbit_ufw_tuple:v6:{$ipv6Rules[0]}",
            )
            ->and($mutations)
            ->toBeEmpty();
    } finally {
        new Filesystem()->deleteDirectory($directory);
    }
})->with([
    'same-comment broader recovery shape' => function (): array {
        $comment = bin2hex('orbit:public-ssh-recovery');

        return [
            ["### tuple ### allow tcp 1:65535 0.0.0.0/0 any 0.0.0.0/0 in comment={$comment}"],
            ["### tuple ### allow tcp 22 ::/0 any ::/0 in comment={$comment}"],
        ];
    },
    'duplicate exact IPv4 recovery ownership' => function (): array {
        $comment = bin2hex('orbit:public-ssh-recovery');
        $ipv4 = "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in comment={$comment}";

        return [
            [$ipv4, $ipv4],
            ["### tuple ### allow tcp 22 ::/0 any ::/0 in comment={$comment}"],
        ];
    },
]);

it('does not reapply exact managed node role firewall rules', function (): void {
    $node = provisionable_node(role: RoleName::AppDev);
    $ssh = new class implements SshExecutor {
        /** @var list<list<string>> */
        public array $arguments = [];

        public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
        {
            $this->arguments[] = $command->arguments;

            return node_success_result($command);
        }
    };
    $converger = new NativeNodeConverger(
        hostKeys: test_scanner(),
        knownHosts: test_known_hosts(),
        sshKeys: test_keys(),
        ssh: $ssh,
        bootstrapCommand: new NodeBootstrapCommandFactory(test_keys()),
        wireGuard: new class implements WireGuardPeerConverger {
            public function converge(Node $node, SshConnection $connection): void {}
        },
        appDevCaddy: new class implements AppDevCaddyManager {
            public function converge(Node $node): void {}
        },
    );

    $converger->converge($node, 'SHA256:pinned');
    $ufwMutations = collect($ssh->arguments)
        ->filter(
            static fn (array $arguments): bool => (
                array_slice(array: $arguments, offset: 0, length: 2) === ['sudo', 'ufw']
                && array_slice(array: $arguments, offset: 0, length: 3) !== ['sudo', 'ufw', 'status']
            ),
        );

    expect($ufwMutations)->toBeEmpty();
});

it('fails closed before mutating UFW when an app-dev comment identifies a broader rule', function (): void {
    $node = provisionable_node(role: RoleName::AppDev);
    $firewallMutations = [];
    $ssh = new class($firewallMutations) implements SshExecutor {
        /** @param list<list<string>> $firewallMutations */
        public function __construct(
            private array &$firewallMutations,
        ) {}

        public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
        {
            if ($command->arguments === ['sudo', 'ufw', 'status', 'numbered']) {
                return new CommandResult(
                    0,
                    <<<'UFW'
                        Status: active

                             To                         Action      From
                             --                         ------      ----
                        [ 1] 80/tcp                     ALLOW IN    Anywhere                   # orbit:app-dev-http
                        UFW,
                    '',
                    10,
                    false,
                );
            }

            if (
                array_slice(array: $command->arguments, offset: 0, length: 2) === ['sudo', 'ufw']
                && array_slice(array: $command->arguments, offset: 0, length: 3) !== ['sudo', 'ufw', 'status']
            ) {
                $this->firewallMutations[] = $command->arguments;
            }

            return node_success_result($command);
        }
    };
    $wireGuard = new class implements WireGuardPeerConverger {
        public function converge(Node $node, SshConnection $connection): void {}
    };
    $converger = new NativeNodeConverger(
        hostKeys: test_scanner(),
        knownHosts: test_known_hosts(),
        sshKeys: test_keys(),
        ssh: $ssh,
        bootstrapCommand: new NodeBootstrapCommandFactory(test_keys()),
        wireGuard: $wireGuard,
        appDevCaddy: new class implements AppDevCaddyManager {
            public function converge(Node $node): void {}
        },
    );

    expect(fn () => $converger->converge($node, 'SHA256:pinned'))
        ->toThrow(function (NodeProvisioningException $exception): void {
            expect($exception->step)
                ->toBe('host-firewall')
                ->and($exception->errorCode)
                ->toBe('node.firewall_convergence_failed');
        });

    expect($firewallMutations)->toBeEmpty();
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
    $expectedFingerprint = 'SHA256:'.str_repeat(string: 'A', times: 43);
    $observedFingerprint = 'SHA256:'.str_repeat(string: 'B', times: 43);
    $converger = fingerprint_guard_converger($knownHostsWrites, $sshCalls, $observedFingerprint);

    expect(fn () => $converger->converge($node, $expectedFingerprint))
        ->toThrow(function (NodeProvisioningException $exception) use (
            $expectedFingerprint,
            $observedFingerprint,
        ): void {
            expect($exception->step)
                ->toBe('ssh-host-key')
                ->and($exception->errorCode)
                ->toBe('node.ssh_host_key_mismatch')
                ->and($exception->getMessage())
                ->toBe('The SSH host fingerprint did not match for node [app-dev].')
                ->not->toContain($expectedFingerprint, $observedFingerprint);
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

            return node_success_result($command);
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
        ->toHaveCount(7)
        ->and($events[0])
        ->toStartWith('root@94.237.40.75:bash -seu -- ')
        ->and($events[1])
        ->toBe('orbit@94.237.40.75:true')
        ->and($events[2])
        ->toBe('orbit@94.237.40.75:sudo ufw status numbered')
        ->and($events[3])
        ->toBe('orbit@94.237.40.75:sudo ufw status numbered')
        ->and($events[4])
        ->toBe('wireguard:orbit@94.237.40.75')
        ->and($events[5])
        ->toBe('orbit@10.44.0.2:true')
        ->and($events[6])
        ->toBe('caddy:app-dev');
});

it('does not converge app-dev Caddy for nodes without the app-dev role', function (): void {
    $node = provisionable_node(name: 'worker', role: RoleName::Gateway);

    $ssh = new class implements SshExecutor {
        public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
        {
            return node_success_result($command);
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
            return node_success_result($command);
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
        'platform' => 'linux',
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

function node_success_result(RemoteCommand $command): CommandResult
{
    if ($command->arguments !== ['sudo', 'ufw', 'status', 'numbered']) {
        return new CommandResult(0, '', '', 10, false);
    }

    return new CommandResult(
        0,
        node_firewall_status([
            'orbit:public-ssh-recovery',
            'orbit:app-dev-http',
            'orbit:app-dev-https',
            'orbit:app-prod-http',
            'orbit:app-prod-https',
            'orbit:gateway-https',
        ]),
        '',
        10,
        false,
    );
}

/** @param list<string> $comments */
function node_firewall_status(array $comments): string
{
    $lines = [
        'orbit:public-ssh-recovery' => [
            '[ 1] 22/tcp                          ALLOW IN    Anywhere                   # orbit:public-ssh-recovery',
            '[ 2] 22/tcp (v6)                     ALLOW IN    Anywhere (v6)              # orbit:public-ssh-recovery',
        ],
        'orbit:app-dev-http' => [
            '[ 3] 10.44.0.2 80/tcp on orbit       ALLOW IN    Anywhere                   # orbit:app-dev-http',
        ],
        'orbit:app-dev-https' => [
            '[ 4] 10.44.0.2 443/tcp on orbit      ALLOW IN    Anywhere                   # orbit:app-dev-https',
        ],
        'orbit:app-prod-http' => [
            '[ 5] 80/tcp                          ALLOW IN    Anywhere                   # orbit:app-prod-http',
            '[ 6] 80/tcp (v6)                     ALLOW IN    Anywhere (v6)              # orbit:app-prod-http',
        ],
        'orbit:app-prod-https' => [
            '[ 7] 443/tcp                         ALLOW IN    Anywhere                   # orbit:app-prod-https',
            '[ 8] 443/tcp (v6)                    ALLOW IN    Anywhere (v6)              # orbit:app-prod-https',
        ],
        'orbit:gateway-https' => [
            '[ 9] 10.44.0.2 443/tcp on orbit      ALLOW IN    Anywhere                   # orbit:gateway-https',
        ],
    ];
    $rules = [];

    foreach ($comments as $comment) {
        array_push($rules, ...$lines[$comment] ?? []);
    }

    return implode("\n", [
        'Status: active',
        '',
        '     To                              Action      From',
        '     --                              ------      ----',
        ...$rules,
        '',
    ]);
}

/** @mago-expect lint:file-name The fake stays beside its single interaction test. */
final class NodeInactiveUfwSshExecutor implements SshExecutor
{
    /** @var list<array{connection: SshConnection, command: RemoteCommand}> */
    public array $calls = [];

    /** @var array<string, true> */
    private array $comments = [];

    private bool $enabled = false;

    private int $storedRuleReads = 0;

    public function __construct(
        private readonly bool $failStoredRecovery = false,
        private readonly bool $storedRuleDrift = false,
        private readonly bool $storedRecoveryWrongShape = false,
    ) {}

    public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
    {
        $this->calls[] = ['connection' => $connection, 'command' => $command];

        if ($command->arguments === ['sudo', 'ufw', 'status', 'numbered']) {
            $output = $this->enabled
                ? node_firewall_status(array_keys($this->comments))
                : "Status: inactive\n";

            return new CommandResult(0, $output, '', 10, false);
        }

        if (array_slice(array: $command->arguments, offset: 0, length: 2) === ['sudo', 'awk']) {
            $this->storedRuleReads++;

            if ($this->failStoredRecovery && $this->storedRuleReads > 1) {
                return new CommandResult(0, '', '', 10, false);
            }

            return new CommandResult(0, $this->storedRules(), '', 10, false);
        }

        if (array_slice(array: $command->arguments, offset: 0, length: 3) === ['sudo', 'ufw', 'allow']) {
            $commentIndex = array_search(needle: 'comment', haystack: $command->arguments, strict: true);
            $comment = is_int($commentIndex) ? $command->arguments[$commentIndex + 1] ?? null : null;

            if (is_string($comment)) {
                $this->comments[$comment] = true;
            }
        }

        if ($command->arguments === ['sudo', 'ufw', '--force', 'enable']) {
            $this->enabled = true;
        }

        return new CommandResult(0, '', '', 10, false);
    }

    private function storedRules(): string
    {
        $rules = [];

        foreach (array_keys($this->comments) as $comment) {
            $encoded = bin2hex($comment);
            $rules[] = "__orbit_ufw_tuple:v4:### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in comment={$encoded}";
            $rules[] = "__orbit_ufw_tuple:v6:### tuple ### allow tcp 22 ::/0 any ::/0 in comment={$encoded}";
        }

        if ($this->storedRuleDrift) {
            $encoded = bin2hex('orbit:app-dev-http');
            $rules[] = "__orbit_ufw_tuple:v4:### tuple ### allow tcp 1:65535 10.44.0.2 any 0.0.0.0/0 in_orbit comment={$encoded}";
        }

        if ($this->storedRecoveryWrongShape) {
            $encoded = bin2hex('orbit:public-ssh-recovery');
            $rules[] = "__orbit_ufw_tuple:v4:### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in_orbit comment={$encoded}";
            $rules[] = "__orbit_ufw_tuple:v6:### tuple ### allow tcp 22 ::/0 any ::/0 in_orbit comment={$encoded}";
        }

        return implode("\n", $rules);
    }
}

/**
 * @param list<string> $knownHostsWrites
 * @param list<string> $sshCalls
 */
function fingerprint_guard_converger(
    array &$knownHostsWrites,
    array &$sshCalls,
    string $observedFingerprint = 'SHA256:pinned',
): NativeNodeConverger {
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
    $hostKeys = new class($observedFingerprint) implements HostKeyScanner {
        public function __construct(
            private string $observedFingerprint,
        ) {}

        public function scan(string $host, int $port): HostKey
        {
            return new HostKey('ssh-ed25519', 'PUBLICKEY', $this->observedFingerprint);
        }
    };

    return new NativeNodeConverger(
        hostKeys: $hostKeys,
        knownHosts: $knownHosts,
        sshKeys: test_keys(),
        ssh: $ssh,
        bootstrapCommand: new NodeBootstrapCommandFactory(test_keys()),
        wireGuard: $wireGuard,
        appDevCaddy: $caddy,
    );
}
