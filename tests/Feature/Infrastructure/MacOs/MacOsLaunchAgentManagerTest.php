<?php

declare(strict_types=1);

use App\Domain\AppDev\RuntimeConvergenceException;
use App\Infrastructure\MacOs\MacOsLaunchAgentManager;
use App\Infrastructure\MacOs\MacOsSshConnectionFactory;
use App\Infrastructure\MacOs\MacOsSteadyStateCommandGuard;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Ssh\HostKey;
use App\Infrastructure\Ssh\HostKeyScanner;
use App\Infrastructure\Ssh\KnownHostsStore;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshConnection;
use App\Infrastructure\Ssh\SshExecutor;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Models\Node;

it('captures loaded and running state and uses user bootout bootstrap for activation and rollback', function (): void {
    $ssh = new MacOsLaunchAgentTestSsh([
        new CommandResult(0, "501\n", '', 1, false),
        new CommandResult(0, "state = running\n", '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(1, '', 'bootstrap failed', 1, false),
        new CommandResult(1, '', 'Could not find service', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
    ]);
    $manager = new MacOsLaunchAgentManager(
        macos_launch_agent_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
    );
    $node = macos_launch_agent_node();
    $state = $manager->snapshot($node, 'com.orbit.caddy');

    expect($state)->toBe(['user_id' => '501', 'loaded' => true, 'running' => true]);
    expect(
        fn () => $manager->activate(
            $node,
            'com.orbit.caddy',
            '/Users/nckrtl/Library/LaunchAgents/com.orbit.caddy.plist',
            $state,
        ),
    )
        ->toThrow(RuntimeConvergenceException::class);

    $manager->restore(
        $node,
        'com.orbit.caddy',
        '/Users/nckrtl/Library/LaunchAgents/com.orbit.caddy.plist',
        $state,
    );

    expect(array_map(static fn (RemoteCommand $command): array => $command->arguments, $ssh->commands))
        ->toBe([
            ['/usr/bin/id', '-u'],
            ['/bin/launchctl', 'print', 'gui/501/com.orbit.caddy'],
            ['/bin/launchctl', 'bootout', 'gui/501/com.orbit.caddy'],
            ['/bin/launchctl', 'bootstrap', 'gui/501', '/Users/nckrtl/Library/LaunchAgents/com.orbit.caddy.plist'],
            ['/bin/launchctl', 'print', 'gui/501/com.orbit.caddy'],
            ['/bin/launchctl', 'bootstrap', 'gui/501', '/Users/nckrtl/Library/LaunchAgents/com.orbit.caddy.plist'],
            ['/bin/launchctl', 'kickstart', '-k', 'gui/501/com.orbit.caddy'],
        ])
        ->and(implode("\n", array_map(
            static fn (RemoteCommand $command): string => implode(' ', $command->arguments),
            $ssh->commands,
        )))
        ->not->toContain('sudo')
        ->not->toContain(':2019');
});

it('restores a loaded but stopped agent and surfaces a stop recovery failure', function (): void {
    $node = macos_launch_agent_node();
    $path = '/Users/nckrtl/Library/LaunchAgents/com.orbit.caddy.plist';
    $state = ['user_id' => '501', 'loaded' => true, 'running' => false];
    $ssh = new MacOsLaunchAgentTestSsh([
        new CommandResult(0, 'state = running', '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, 'state = stopped', '', 1, false),
    ]);
    $manager = new MacOsLaunchAgentManager(macos_launch_agent_connections(), $ssh, new MacOsSteadyStateCommandGuard);

    $manager->restore($node, 'com.orbit.caddy', $path, $state);

    expect(array_map(static fn (RemoteCommand $command): array => $command->arguments, $ssh->commands))->toBe([
        ['/bin/launchctl', 'print', 'gui/501/com.orbit.caddy'],
        ['/bin/launchctl', 'bootout', 'gui/501/com.orbit.caddy'],
        ['/bin/launchctl', 'bootstrap', 'gui/501', $path],
        ['/bin/launchctl', 'stop', 'gui/501/com.orbit.caddy'],
        ['/bin/launchctl', 'print', 'gui/501/com.orbit.caddy'],
    ]);

    $failingSsh = new MacOsLaunchAgentTestSsh([
        new CommandResult(1, '', 'Could not find service', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(1, '', 'stop failed', 1, false),
    ]);
    $failingManager = new MacOsLaunchAgentManager(
        macos_launch_agent_connections(),
        $failingSsh,
        new MacOsSteadyStateCommandGuard,
    );
    expect(fn () => $failingManager->restore($node, 'com.orbit.caddy', $path, $state))
        ->toThrow(RuntimeConvergenceException::class);
});

it('fences each launchd command with the exact live target lease', function (): void {
    $ssh = new MacOsLaunchAgentTestSsh([
        new CommandResult(0, "501\n", '', 1, false),
        new CommandResult(0, "state = running\n", '', 1, false),
    ]);
    $manager = new MacOsLaunchAgentManager(
        macos_launch_agent_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
    );
    $token = str_repeat('012345', times: 4);
    $lease = [
        'lock_path' => '/Users/nckrtl/.orbit/run/caddy.lock',
        'token' => $token,
    ];

    expect($manager->snapshot(macos_launch_agent_node(), 'com.orbit.caddy', $lease))
        ->toBe(['user_id' => '501', 'loaded' => true, 'running' => true]);

    foreach ($ssh->commands as $command) {
        expect($command->arguments)
            ->toContain(
                '/Users/nckrtl/.orbit/run/caddy.lock',
                $token,
            )
            ->and($command->input)
            ->toContain(
                'test "$current_token" = "$token"',
                'kill -0 "$keeper_pid" 2>/dev/null',
                'orbit-lease-keeper $token $lock_path',
                'exec "$@"',
            );
    }
});

it('accepts only exact native absence and recognized launchd states while snapshotting', function (): void {
    $node = macos_launch_agent_node();

    foreach ([
        'bare native absence' => new CommandResult(1, '', 'Could not find service', 1, false),
        'canonical dynamic absence' => new CommandResult(
            1,
            '',
            'Could not find service "com.orbit.caddy" in domain for user gui: 501',
            1,
            false,
        ),
    ] as $result) {
        $manager = new MacOsLaunchAgentManager(
            macos_launch_agent_connections(),
            new MacOsLaunchAgentTestSsh([
                new CommandResult(0, "501\n", '', 1, false),
                $result,
            ]),
            new MacOsSteadyStateCommandGuard,
        );

        expect($manager->snapshot($node, 'com.orbit.caddy'))
            ->toBe(['user_id' => '501', 'loaded' => false, 'running' => false]);
    }

    foreach ([
        'lookalike absence' => new CommandResult(
            1,
            '',
            'Could not find service "com.orbit.caddy" in domain for user gui: 501; transport failed',
            1,
            false,
        ),
        'arbitrary failure' => new CommandResult(1, '', 'connection reset', 1, false),
        'ambiguous successful state' => new CommandResult(0, 'state = confused', '', 1, false),
        'conflicting recognized states' => new CommandResult(
            0,
            "state = running\nstate = not running\n",
            '',
            1,
            false,
        ),
        'recognized and unknown states' => new CommandResult(
            0,
            "state = running\nstate = confused\n",
            '',
            1,
            false,
        ),
    ] as $result) {
        $manager = new MacOsLaunchAgentManager(
            macos_launch_agent_connections(),
            new MacOsLaunchAgentTestSsh([
                new CommandResult(0, "501\n", '', 1, false),
                $result,
            ]),
            new MacOsSteadyStateCommandGuard,
        );

        expect(fn (): array => $manager->snapshot($node, 'com.orbit.caddy'))
            ->toThrow(RuntimeConvergenceException::class, 'macOS launch agent operation failed');
    }
});

it('rejects ambiguous launchctl state while restoring instead of treating it as absent', function (): void {
    $manager = new MacOsLaunchAgentManager(
        macos_launch_agent_connections(),
        new MacOsLaunchAgentTestSsh([
            new CommandResult(1, '', 'Could not find service with appended diagnostic', 1, false),
        ]),
        new MacOsSteadyStateCommandGuard,
    );

    expect(fn () => $manager->restore(
        macos_launch_agent_node(),
        'com.orbit.caddy',
        '/Users/nckrtl/Library/LaunchAgents/com.orbit.caddy.plist',
        ['user_id' => '501', 'loaded' => false, 'running' => false],
    ))
        ->toThrow(RuntimeConvergenceException::class, 'macOS launch agent operation failed');
});

function macos_launch_agent_node(): Node
{
    $node = new Node([
        'platform' => 'darwin',
        'architecture' => 'arm64',
        'ssh_user' => 'nckrtl',
        'wireguard_address' => '10.44.0.9',
    ]);
    $node->id = 9;
    $node->setRelation('roles', new \Illuminate\Database\Eloquent\Collection([
        new \App\Models\NodeRole([
            'role' => \App\Domain\Nodes\RoleName::AppDev,
            'status' => \App\Domain\Shared\LifecycleStatus::Active,
        ]),
    ]));

    return $node;
}

function macos_launch_agent_connections(): MacOsSshConnectionFactory
{
    return new MacOsSshConnectionFactory(
        new class implements HostKeyScanner {
            public function scan(string $host, int $port): HostKey
            {
                return new HostKey('ssh-ed25519', 'AAAAC3', 'SHA256:test');
            }
        },
        new class implements KnownHostsStore {
            public function path(): string
            {
                return '/tmp/orbit-known-hosts';
            }

            public function put(string $host, int $port, HostKey $key): void {}
        },
        new class implements SshKeyProvider {
            public function privateKeyPath(): string
            {
                return '/tmp/orbit-key';
            }

            public function publicKey(): string
            {
                return 'ssh-ed25519 AAAA gateway';
            }
        },
    );
}

/** @mago-expect lint:file-name Test-local SSH fake keeps exact launchd state transitions observable. */
final class MacOsLaunchAgentTestSsh implements SshExecutor
{
    /** @var list<RemoteCommand> */
    public array $commands = [];

    /** @param list<CommandResult> $results */
    public function __construct(
        private array $results,
    ) {}

    public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
    {
        $this->commands[] = $command;

        return array_shift($this->results) ?? new CommandResult(0, '', '', 1, false);
    }
}
