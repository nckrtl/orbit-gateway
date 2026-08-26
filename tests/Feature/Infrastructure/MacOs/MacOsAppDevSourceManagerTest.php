<?php

declare(strict_types=1);

use App\Domain\AppDev\AppDevHostPaths;
use App\Domain\AppDev\AppDevSourceOperationLock;
use App\Infrastructure\MacOs\MacOsAppDevSourceManager;
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
use App\Models\App as OrbitApp;
use App\Models\Instance;
use App\Models\Node;
use App\Models\Workspace;

it('uses the shared source lock and exact Darwin primary and worktree ownership gates', function (): void {
    [$instance, $workspace] = macos_source_models();
    $lock = new MacOsSourceTestLock;
    $ssh = new MacOsSourceTestSsh($lock);
    $manager = new MacOsAppDevSourceManager(
        paths: new AppDevHostPaths,
        connections: macos_source_connections(),
        ssh: $ssh,
        guard: new MacOsSteadyStateCommandGuard,
        lock: $lock,
    );

    $manager->convergeInstance($instance);
    $manager->convergeWorkspace($workspace);
    $manager->removeWorkspace($workspace);
    $manager->removeInstance($instance);

    expect($lock->nodeIds)
        ->toBe([9, 9, 9, 9])
        ->and($ssh->commands)
        ->toHaveCount(4)
        ->and(array_map(static fn (SshConnection $connection): string => $connection->user, $ssh->connections))
        ->toBe(['nckrtl', 'nckrtl', 'nckrtl', 'nckrtl'])
        ->and($ssh->commands[0]->arguments)
        ->toContain('git@github.com:acme/site.git', '/Users/nckrtl/apps/acme')
        ->and($ssh->commands[0]->input)
        ->toContain(
            'git clone -- "$repository" "$checkout"',
            'remote get-url origin',
            'rev-parse --show-toplevel',
        )
        ->not->toContain('sudo')
        ->not->toContain('setfacl')->and($ssh->commands[1]->arguments)->toContain(
            '/Users/nckrtl/apps/acme',
            '/Users/nckrtl/.orbit/worktrees/acme/feature-one',
            'feature/one',
        )->and($ssh->commands[1]->input)->toContain(
            'worktree list --porcelain',
            'symbolic-ref --quiet --short HEAD',
            'for managed_directory in "$orbit_root" "$worktrees_root" "$app_worktrees"',
            'test ! -L "$managed_directory"',
            'worktree add -- "$checkout" "$branch"',
            'worktree add -b "$branch" -- "$checkout" HEAD',
        )->and($ssh->commands[2]->input)->toContain(
            'worktree list --porcelain',
            'test "$registered_branch" = "$branch"',
            'test "$(git -C "$instance" remote get-url origin)" = "$repository"',
            'worktree remove --force -- "$checkout"',
            'test ! -e "$checkout"',
        )
        ->not->toContain('rm -rf')->and($ssh->commands[3]->input)->toContain(
            'worktree list --porcelain',
            'find -P "$checkout" -depth -delete',
        )
        ->not->toContain('rm -rf');
});

it('rejects stored Darwin path drift before SSH', function (): void {
    [$instance] = macos_source_models();
    $instance->checkout_path = '/Users/nckrtl/apps/foreign';
    $lock = new MacOsSourceTestLock;
    $ssh = new MacOsSourceTestSsh($lock);
    $manager = new MacOsAppDevSourceManager(
        new AppDevHostPaths,
        macos_source_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        $lock,
    );

    expect(fn () => $manager->convergeInstance($instance))
        ->toThrow(\App\Domain\Shared\ResourceOperationException::class);
    expect($ssh->commands)->toBeEmpty();
});

it('does not treat dangling symlink instance or workspace removal targets as absent', function (): void {
    [$instance, $workspace] = macos_source_models();
    $lock = new MacOsSourceTestLock;
    $ssh = new MacOsSourceTestSsh($lock);
    $manager = new MacOsAppDevSourceManager(
        new AppDevHostPaths,
        macos_source_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        $lock,
    );

    $manager->removeInstance($instance);
    $manager->removeWorkspace($workspace);

    expect($ssh->commands[0]->input)
        ->toContain('if [ ! -e "$checkout" ] && [ ! -L "$checkout" ]; then')
        ->and($ssh->commands[1]->input)
        ->toContain(<<<'BASH'
            then
                test ! -e "$checkout"
                test ! -L "$checkout"
                exit 0
            fi
            BASH);
});

it('does not follow dangling symlink instance clone or workspace add targets', function (): void {
    [$instance, $workspace] = macos_source_models();
    $lock = new MacOsSourceTestLock;
    $ssh = new MacOsSourceTestSsh($lock);
    $manager = new MacOsAppDevSourceManager(
        new AppDevHostPaths,
        macos_source_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        $lock,
    );

    $manager->convergeInstance($instance);
    $manager->convergeWorkspace($workspace);

    expect($ssh->commands[0]->input)
        ->toContain(<<<'BASH'
            else
                test ! -L "$checkout"
                git clone -- "$repository" "$checkout"
            fi
            BASH)
        ->and($ssh->commands[1]->input)
        ->toContain(<<<'BASH'
            else
                test ! -e "$checkout"
                test ! -L "$checkout"
            BASH);
});

/** @return array{Instance, Workspace} */
function macos_source_models(): array
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
    $app = new OrbitApp(['slug' => 'acme', 'repository_url' => 'git@github.com:acme/site.git']);
    $instance = new Instance([
        'node_id' => 9,
        'name' => 'dev',
        'checkout_path' => '/Users/nckrtl/apps/acme',
        'document_root' => 'public',
    ]);
    $instance->setRelation('node', $node);
    $instance->setRelation('app', $app);
    $workspace = new Workspace([
        'name' => 'feature-one',
        'checkout_path' => '/Users/nckrtl/.orbit/worktrees/acme/feature-one',
        'branch' => 'feature/one',
    ]);
    $workspace->setRelation('instance', $instance);

    return [$instance, $workspace];
}

function macos_source_connections(): MacOsSshConnectionFactory
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

final class MacOsSourceTestLock implements AppDevSourceOperationLock
{
    /** @var list<int> */
    public array $nodeIds = [];
    public bool $held = false;

    public function synchronized(int $nodeId, Closure $operation): mixed
    {
        $this->nodeIds[] = $nodeId;
        $this->held = true;

        try {
            return $operation();
        } finally {
            $this->held = false;
        }
    }
}

/** @mago-expect lint:single-class-per-file Test-local SSH fake keeps source lock and command order observable. */
final class MacOsSourceTestSsh implements SshExecutor
{
    /** @var list<RemoteCommand> */
    public array $commands = [];
    /** @var list<SshConnection> */
    public array $connections = [];

    public function __construct(
        private MacOsSourceTestLock $lock,
    ) {}

    public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
    {
        expect($this->lock->held)->toBeTrue();
        $this->connections[] = $connection;
        $this->commands[] = $command;

        return new CommandResult(0, '', '', 1, false);
    }
}
