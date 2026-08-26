<?php

declare(strict_types=1);

use App\Domain\AppDev\AppDevHostPaths;
use App\Domain\AppDev\AppDevSourceOperationLock;
use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\Instances\CertificateMode;
use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Infrastructure\AppDev\AppDevSiteRepository;
use App\Infrastructure\MacOs\MacOsAppDevCaddyConfigRenderer;
use App\Infrastructure\MacOs\MacOsAppDevCaddyManager;
use App\Infrastructure\MacOs\MacOsFilesystemLayout;
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
use App\Models\App as OrbitApp;
use App\Models\Instance;
use App\Models\Node;
use Symfony\Component\Process\Process as SymfonyProcess;
use Symfony\Component\Process\Process;

it('validates exact adapted listeners before an atomic Caddy switch and user launchd reload', function (): void {
    $node = macos_caddy_models();
    $lock = new MacOsCaddyTestLock;
    $layout = new MacOsFilesystemLayout;
    $repository = new AppDevSiteRepository(new AppDevHostPaths);
    $configuration = new MacOsAppDevCaddyConfigRenderer($layout)->render($repository->forNode($node), '10.44.0.9');
    $adapt = new Process(['caddy', 'adapt', '--config', '-', '--adapter', 'caddyfile']);
    $adapt->setInput($configuration);
    $adapt->mustRun();
    $adapted = $adapt->getOutput();
    $ssh = new MacOsCaddyTestSsh([
        new CommandResult(0, $adapted, '', 1, false),
        new CommandResult(0, "ACQUIRED\n", '', 1, false),
        new CommandResult(0, "501\n", '', 1, false),
        new CommandResult(0, "state = running\n", '', 1, false),
        new CommandResult(0, "CHANGED\n", '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
    ], $lock);
    $connections = macos_caddy_connections();
    $guard = new MacOsSteadyStateCommandGuard;
    $manager = new MacOsAppDevCaddyManager(
        $repository,
        new MacOsAppDevCaddyConfigRenderer($layout),
        new AppDevHostPaths,
        $layout,
        $connections,
        $ssh,
        $guard,
        new MacOsLaunchAgentManager($connections, $ssh, $guard),
        $lock,
    );

    $manager->converge($node);

    $commands = array_map(static fn (RemoteCommand $command): array => $command->arguments, $ssh->commands);
    $publish = $ssh->commands[4]->input ?? '';
    expect($lock->nodeIds)
        ->toBe([$node->id])
        ->and($commands[0])
        ->toBe(['/opt/homebrew/opt/caddy/bin/caddy', 'adapt', '--config', '-', '--adapter', 'caddyfile', '--validate'])
        ->and($commands[5])
        ->toContain('/bin/launchctl', 'bootout')
        ->and($commands[6])
        ->toContain(
            '/bin/launchctl',
            'bootstrap',
            '/Users/nckrtl/Library/LaunchAgents/com.orbit.caddy.plist',
        )
        ->and($ssh->commands[4]->arguments)
        ->toContain('/Users/nckrtl/.orbit/caddy/Caddyfile', '/Users/nckrtl/.orbit/run/caddy.lock')
        ->and($publish)
        ->toContain(
            '"$caddy" adapt --config "$candidate_configuration" --adapter caddyfile --validate',
            'snapshot_path "$live_configuration" configuration',
            'snapshot_path "$plist" plist',
            'mv -h -f -- "$configuration_link" "$live_configuration"',
        )
        ->not->toContain('sudo')
        ->not->toContain(':2019')
        ->not->toContain('reload')->and(mb_strpos(
            haystack: $publish,
            needle: 'adapt --config "$candidate_configuration"',
        ))->toBeLessThan(mb_strpos(
            haystack: $publish,
            needle: 'mv -h -f -- "$configuration_link"',
        ))->and(implode("\n", array_map(
            static fn (RemoteCommand $command): string => implode(' ', $command->arguments).($command->input ?? ''),
            $ssh->commands,
        )))
        ->not->toContain('sudo')
        ->not->toContain(':2019');
});

it('rejects wildcard loopback public UDP HTTP 3 and admin adaptation before publication', function (array $server): void {
    $node = macos_caddy_models();
    $lock = new MacOsCaddyTestLock;
    $ssh = new MacOsCaddyTestSsh([
        new CommandResult(
            0,
            json_encode(['apps' => ['http' => ['servers' => ['bad' => $server]]]], JSON_THROW_ON_ERROR),
            '',
            1,
            false,
        ),
    ], $lock);
    $connections = macos_caddy_connections();
    $guard = new MacOsSteadyStateCommandGuard;
    $layout = new MacOsFilesystemLayout;
    $manager = new MacOsAppDevCaddyManager(
        new AppDevSiteRepository(new AppDevHostPaths),
        new MacOsAppDevCaddyConfigRenderer($layout),
        new AppDevHostPaths,
        $layout,
        $connections,
        $ssh,
        $guard,
        new MacOsLaunchAgentManager($connections, $ssh, $guard),
        $lock,
    );

    expect(fn () => $manager->converge($node))->toThrow(RuntimeConvergenceException::class);
    expect($ssh->commands)->toHaveCount(1);
})->with([
    'wildcard' => [['listen' => ['0.0.0.0:8080']]],
    'loopback' => [['listen' => ['127.0.0.1:8080']]],
    'public' => [['listen' => ['192.0.2.9:8443']]],
    'UDP' => [['listen' => ['udp/10.44.0.9:8443']]],
    'HTTP 3' => [['listen' => ['10.44.0.9:8443'], 'protocols' => ['h1', 'h2', 'h3']]],
    'admin listener' => [['listen' => ['10.44.0.9:2019']]],
]);

it('rejects an absent or listening Caddy admin configuration', function (array $admin): void {
    $node = macos_caddy_models();
    $lock = new MacOsCaddyTestLock;
    $ssh = new MacOsCaddyTestSsh([
        new CommandResult(
            0,
            json_encode([
                ...$admin,
                'apps' => [
                    'http' => [
                        'servers' => [
                            'http' => ['listen' => ['10.44.0.9:8080']],
                            'https' => ['listen' => ['10.44.0.9:8443'], 'protocols' => ['h1', 'h2']],
                        ],
                    ],
                ],
            ], JSON_THROW_ON_ERROR),
            '',
            1,
            false,
        ),
    ], $lock);
    $connections = macos_caddy_connections();
    $guard = new MacOsSteadyStateCommandGuard;
    $layout = new MacOsFilesystemLayout;
    $manager = new MacOsAppDevCaddyManager(
        new AppDevSiteRepository(new AppDevHostPaths),
        new MacOsAppDevCaddyConfigRenderer($layout),
        new AppDevHostPaths,
        $layout,
        $connections,
        $ssh,
        $guard,
        new MacOsLaunchAgentManager($connections, $ssh, $guard),
        $lock,
    );

    expect(fn () => $manager->converge($node))->toThrow(RuntimeConvergenceException::class);
})->with([
    'absent admin uses the default listener' => [[]],
    'explicit default admin listener' => [['admin' => ['listen' => 'localhost:2019']]],
    'other admin listener' => [['admin' => ['listen' => '10.44.0.9:2020']]],
]);

it('rejects an otherwise valid adaptation with a listener outside the HTTP app', function (): void {
    $node = macos_caddy_models();
    $lock = new MacOsCaddyTestLock;
    $adapted = json_encode([
        'admin' => ['disabled' => true],
        'apps' => [
            'http' => [
                'servers' => [
                    'http' => ['listen' => ['10.44.0.9:8080']],
                    'https' => ['listen' => ['10.44.0.9:8443'], 'protocols' => ['h1', 'h2']],
                ],
            ],
            'layer4' => ['servers' => ['extra' => ['listen' => ['10.44.0.9:9000']]]],
        ],
    ], JSON_THROW_ON_ERROR);
    $ssh = new MacOsCaddyTestSsh([new CommandResult(0, $adapted, '', 1, false)], $lock);
    $connections = macos_caddy_connections();
    $guard = new MacOsSteadyStateCommandGuard;
    $layout = new MacOsFilesystemLayout;
    $manager = new MacOsAppDevCaddyManager(
        new AppDevSiteRepository(new AppDevHostPaths),
        new MacOsAppDevCaddyConfigRenderer($layout),
        new AppDevHostPaths,
        $layout,
        $connections,
        $ssh,
        $guard,
        new MacOsLaunchAgentManager($connections, $ssh, $guard),
        $lock,
    );

    expect(fn () => $manager->converge($node))->toThrow(RuntimeConvergenceException::class);
    expect($ssh->commands)->toHaveCount(1);
});

it('fails before Caddy mutation when a runtime or LaunchAgents ancestor is a symlink', function (): void {
    $node = macos_caddy_models();
    $lock = new MacOsCaddyTestLock;
    $ssh = new MacOsCaddyTestSsh([
        new CommandResult(0, macos_caddy_adapted_configuration(), '', 1, false),
        new CommandResult(1, '', 'ancestor symlink', 1, false),
    ], $lock);
    $connections = macos_caddy_connections();
    $guard = new MacOsSteadyStateCommandGuard;
    $layout = new MacOsFilesystemLayout;
    $manager = new MacOsAppDevCaddyManager(
        new AppDevSiteRepository(new AppDevHostPaths),
        new MacOsAppDevCaddyConfigRenderer($layout),
        new AppDevHostPaths,
        $layout,
        $connections,
        $ssh,
        $guard,
        new MacOsLaunchAgentManager($connections, $ssh, $guard),
        $lock,
    );

    expect(fn () => $manager->converge($node))->toThrow(RuntimeConvergenceException::class);

    $script = $ssh->commands[1]->input ?? '';
    expect($ssh->commands)
        ->toHaveCount(2)
        ->and($script)
        ->toContain(
            '"$home/.orbit"',
            '"$home/.orbit/run"',
            '"$home/.orbit/caddy"',
            '"$home/Library/LaunchAgents"',
            'if [ -L "$managed_directory" ]; then exit 1; fi',
        );
});

it('holds the exact target Caddy lease across snapshot publication activation cleanup and release', function (): void {
    $node = macos_caddy_models();
    $lock = new MacOsCaddyTestLock;
    $ssh = new MacOsCaddyTestSsh([
        new CommandResult(0, macos_caddy_adapted_configuration(), '', 1, false),
        new CommandResult(0, "ACQUIRED\n", '', 1, false),
        new CommandResult(0, "501\n", '', 1, false),
        new CommandResult(0, "state = running\n", '', 1, false),
        new CommandResult(0, "CHANGED\n", '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
    ], $lock);
    $connections = macos_caddy_connections();
    $guard = new MacOsSteadyStateCommandGuard;
    $layout = new MacOsFilesystemLayout;
    $manager = new MacOsAppDevCaddyManager(
        new AppDevSiteRepository(new AppDevHostPaths),
        new MacOsAppDevCaddyConfigRenderer($layout),
        new AppDevHostPaths,
        $layout,
        $connections,
        $ssh,
        $guard,
        new MacOsLaunchAgentManager($connections, $ssh, $guard),
        $lock,
    );

    $manager->converge($node);

    expect($ssh->commands)
        ->toHaveCount(9)
        ->and($ssh->commands[1]->arguments)
        ->toContain('/Users/nckrtl/.orbit/run/caddy.lock')
        ->and($ssh->commands[1]->input)
        ->toContain(
            'mkdir -- "$lock_path"',
            'stale_lock="$lock_path.stale-$previous_token"',
            'mv -h -- "$lock_path" "$stale_lock"',
            'keeper_pid=$!',
            'kill -0 "$previous_keeper_pid"',
            'previous_keeper_command=$(/bin/ps -ww -p "$previous_keeper_pid" -o command=)',
            '/usr/bin/nohup /bin/sh -c',
            '</dev/null >/dev/null 2>&1 &',
        )
        ->and($ssh->commands[1]->input)
        ->not->toContain('now - previous_acquired_at')
        ->not->toContain('stale-unknown')->and(mb_strpos(
            haystack: $ssh->commands[1]->input ?? '',
            needle: 'mkdir -- "$lock_path"',
        ))->toBeLessThan(mb_strpos(
            haystack: $ssh->commands[1]->input ?? '',
            needle: 'for managed_directory in "$home/.orbit/caddy"',
        ))->and($ssh->commands[2]->arguments)->toContain(
            '/Users/nckrtl/.orbit/run/caddy.lock',
        )->and($ssh->commands[2]->input)->toContain(
            'test "$current_token" = "$token"',
            'kill -0 "$keeper_pid"',
            'orbit-lease-keeper $token $lock_path',
            'exec "$@"',
        )->and($ssh->commands[4]->input)->toContain(
            'test "$current_token" = "$token"',
            'for managed_directory in "$caddy_root" "$caddy_root/versions" "$rollback_parent" "$plist_parent"',
            'test ! -L "$managed_directory"',
            'adapted_json=$("$caddy" adapt --config "$candidate_configuration" --adapter caddyfile --validate)',
            'actual_adapted_hash=$(printf \'%s\' "$adapted_json" | /usr/bin/shasum -a 256 | /usr/bin/awk \'{print $1}\')',
            'test "$actual_adapted_hash" = "$expected_adapted_hash"',
        )->and($ssh->commands[7]->arguments[0] ?? null)->toBe('/bin/bash')->and($ssh->commands[8]->input)->toContain(
            'test "$current_token" = "$token"',
            'rmdir -- "$lock_path"',
        );
});

it('rejects a competing Caddy writer before launchd snapshot while preserving the fixed lock owner', function (): void {
    $node = macos_caddy_models();
    $lock = new MacOsCaddyTestLock;
    $ssh = new MacOsCaddyTestSsh([
        new CommandResult(0, macos_caddy_adapted_configuration(), '', 1, false),
        new CommandResult(75, '', 'lock held', 1, false),
    ], $lock);
    $connections = macos_caddy_connections();
    $guard = new MacOsSteadyStateCommandGuard;
    $layout = new MacOsFilesystemLayout;
    $manager = new MacOsAppDevCaddyManager(
        new AppDevSiteRepository(new AppDevHostPaths),
        new MacOsAppDevCaddyConfigRenderer($layout),
        new AppDevHostPaths,
        $layout,
        $connections,
        $ssh,
        $guard,
        new MacOsLaunchAgentManager($connections, $ssh, $guard),
        $lock,
    );

    expect(fn () => $manager->converge($node))->toThrow(RuntimeConvergenceException::class);
    expect($ssh->commands)
        ->toHaveCount(2)
        ->and($ssh->commands[1]->arguments)
        ->toContain('/Users/nckrtl/.orbit/run/caddy.lock')
        ->and($ssh->commands[1]->input)
        ->toContain(
            'if kill -0 "$previous_keeper_pid" 2>/dev/null; then',
            'exit 75',
            'mv -h -- "$lock_path" "$stale_lock"',
        )
        ->not->toContain('rm -rf')
        ->not->toContain('find -P "$lock_path" -delete')
        ->not->toContain('now - previous_acquired_at');
});

it('preserves the Caddy rollback failure when lease release also fails', function (): void {
    $node = macos_caddy_models();
    $adapted = macos_caddy_adapted_configuration();
    $lock = new MacOsCaddyTestLock;
    $connections = macos_caddy_connections();
    $guard = new MacOsSteadyStateCommandGuard;
    $layout = new MacOsFilesystemLayout;
    $contendedSsh = new MacOsCaddyTestSsh([
        new CommandResult(0, $adapted, '', 1, false),
        new CommandResult(75, '', 'lock held', 1, false),
    ], $lock);
    $contended = new MacOsAppDevCaddyManager(
        new AppDevSiteRepository(new AppDevHostPaths),
        new MacOsAppDevCaddyConfigRenderer($layout),
        new AppDevHostPaths,
        $layout,
        $connections,
        $contendedSsh,
        $guard,
        new MacOsLaunchAgentManager($connections, $contendedSsh, $guard),
        $lock,
    );

    expect(fn () => $contended->converge($node))->toThrow(RuntimeConvergenceException::class);
    expect($contendedSsh->commands)->toHaveCount(2);

    $rollbackSsh = new MacOsCaddyTestSsh([
        new CommandResult(0, $adapted, '', 1, false),
        new CommandResult(0, "ACQUIRED\n", '', 1, false),
        new CommandResult(0, "501\n", '', 1, false),
        new CommandResult(0, 'state = running', '', 1, false),
        new CommandResult(0, "CHANGED\n", '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(1, '', 'bootstrap failed', 1, false),
        new CommandResult(1, '', 'file rollback failed', 1, false),
        new CommandResult(1, '', 'Could not find service', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(1, '', 'release failed', 1, false),
    ], $lock);
    $rollback = new MacOsAppDevCaddyManager(
        new AppDevSiteRepository(new AppDevHostPaths),
        new MacOsAppDevCaddyConfigRenderer($layout),
        new AppDevHostPaths,
        $layout,
        $connections,
        $rollbackSsh,
        $guard,
        new MacOsLaunchAgentManager($connections, $rollbackSsh, $guard),
        $lock,
    );

    try {
        $rollback->converge($node);
        $this->fail('Expected the Caddy rollback to fail.');
    } catch (RuntimeConvergenceException $exception) {
        expect($exception->step)
            ->toBe('caddy-rollback')
            ->and($exception->errorCode)
            ->toBe('app-dev.caddy_rollback_failed');
    }
});

it('can retry Caddy convergence after a successful rollback', function (): void {
    $node = macos_caddy_models();
    $lock = new MacOsCaddyTestLock;
    $connections = macos_caddy_connections();
    $guard = new MacOsSteadyStateCommandGuard;
    $layout = new MacOsFilesystemLayout;
    $adapted = macos_caddy_adapted_configuration();
    $ssh = new MacOsCaddyTestSsh([
        new CommandResult(0, $adapted, '', 1, false),
        new CommandResult(0, "ACQUIRED\n", '', 1, false),
        new CommandResult(0, "501\n", '', 1, false),
        new CommandResult(0, 'state = running', '', 1, false),
        new CommandResult(0, "CHANGED\n", '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(1, '', 'bootstrap failed', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(1, '', 'Could not find service', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, $adapted, '', 1, false),
        new CommandResult(0, "ACQUIRED\n", '', 1, false),
        new CommandResult(0, "501\n", '', 1, false),
        new CommandResult(0, 'state = running', '', 1, false),
        new CommandResult(0, "CHANGED\n", '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
    ], $lock);
    $manager = new MacOsAppDevCaddyManager(
        new AppDevSiteRepository(new AppDevHostPaths),
        new MacOsAppDevCaddyConfigRenderer($layout),
        new AppDevHostPaths,
        $layout,
        $connections,
        $ssh,
        $guard,
        new MacOsLaunchAgentManager($connections, $ssh, $guard),
        $lock,
    );

    expect(fn () => $manager->converge($node))->toThrow(RuntimeConvergenceException::class);
    $manager->converge($node);

    expect($lock->nodeIds)->toBe([$node->id, $node->id])->and($ssh->commands)->toHaveCount(21);
});

it('restores Caddy state after an ambiguous exit 255 publication result', function (): void {
    $node = macos_caddy_models();
    $lock = new MacOsCaddyTestLock;
    $connections = macos_caddy_connections();
    $guard = new MacOsSteadyStateCommandGuard;
    $layout = new MacOsFilesystemLayout;
    $ssh = new MacOsCaddyTestSsh([
        new CommandResult(0, macos_caddy_adapted_configuration(), '', 1, false),
        new CommandResult(0, "ACQUIRED\n", '', 1, false),
        new CommandResult(0, "501\n", '', 1, false),
        new CommandResult(0, "state = running\n", '', 1, false),
        new CommandResult(255, '', 'transport outcome unknown', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(1, '', 'Could not find service', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
    ], $lock);
    $manager = macos_caddy_manager($connections, $ssh, $guard, $layout, $lock);

    try {
        $manager->converge($node);
        $this->fail('Expected the ambiguous Caddy publication to fail.');
    } catch (RuntimeConvergenceException $exception) {
        expect($exception->step)
            ->toBe('caddy-config')
            ->and($exception->errorCode)
            ->toBe('app-dev.caddy_config_failed')
            ->and($exception->result?->exitCode)
            ->toBe(255);
    }

    expect($ssh->commands[5]->input ?? '')
        ->toContain('restore_path "$live_configuration" configuration');
});

it('restores Caddy state after a thrown publication transport failure', function (): void {
    $node = macos_caddy_models();
    $lock = new MacOsCaddyTestLock;
    $connections = macos_caddy_connections();
    $guard = new MacOsSteadyStateCommandGuard;
    $layout = new MacOsFilesystemLayout;
    $ssh = new MacOsCaddyTestSsh([
        new CommandResult(0, macos_caddy_adapted_configuration(), '', 1, false),
        new CommandResult(0, "ACQUIRED\n", '', 1, false),
        new CommandResult(0, "501\n", '', 1, false),
        new CommandResult(0, "state = running\n", '', 1, false),
        new RuntimeException('publication transport sentinel'),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(1, '', 'Could not find service', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
    ], $lock);
    $manager = macos_caddy_manager($connections, $ssh, $guard, $layout, $lock);

    try {
        $manager->converge($node);
        $this->fail('Expected the thrown Caddy publication to fail.');
    } catch (RuntimeConvergenceException $exception) {
        expect($exception->step)
            ->toBe('caddy-config')
            ->and($exception->errorCode)
            ->toBe('app-dev.caddy_config_failed')
            ->and($exception->getMessage())
            ->not->toContain('publication transport sentinel');
    }

    expect($ssh->commands[5]->input ?? '')
        ->toContain('restore_path "$live_configuration" configuration');
});

it('does not start a second Caddy rollback for a deterministic publication failure', function (): void {
    $node = macos_caddy_models();
    $lock = new MacOsCaddyTestLock;
    $connections = macos_caddy_connections();
    $guard = new MacOsSteadyStateCommandGuard;
    $layout = new MacOsFilesystemLayout;
    $ssh = new MacOsCaddyTestSsh([
        new CommandResult(0, macos_caddy_adapted_configuration(), '', 1, false),
        new CommandResult(0, "ACQUIRED\n", '', 1, false),
        new CommandResult(0, "501\n", '', 1, false),
        new CommandResult(0, "state = running\n", '', 1, false),
        new CommandResult(73, '', 'deterministic validation failure', 1, false),
        new CommandResult(0, '', '', 1, false),
    ], $lock);

    expect(fn () => macos_caddy_manager($connections, $ssh, $guard, $layout, $lock)->converge($node))
        ->toThrow(RuntimeConvergenceException::class);
    expect($ssh->commands)
        ->toHaveCount(6)
        ->and($ssh->commands[5]->input ?? '')
        ->toContain('rmdir -- "$lock_path"')
        ->not->toContain('restore_path "$live_configuration" configuration');
});

/** @mago-expect lint:halstead Exact recovery-script assertions keep all immediate mutation gates together. */
it('revalidates Caddy rollback and cleanup parents artifacts ownership modes and plist label', function (): void {
    $node = macos_caddy_models();
    $lock = new MacOsCaddyTestLock;
    $connections = macos_caddy_connections();
    $guard = new MacOsSteadyStateCommandGuard;
    $layout = new MacOsFilesystemLayout;
    $ssh = new MacOsCaddyTestSsh([
        new CommandResult(0, macos_caddy_adapted_configuration(), '', 1, false),
        new CommandResult(0, "ACQUIRED\n", '', 1, false),
        new CommandResult(0, "501\n", '', 1, false),
        new CommandResult(0, "state = running\n", '', 1, false),
        new CommandResult(0, "CHANGED\n", '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(1, '', 'bootstrap failed', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(1, '', 'Could not find service', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
    ], $lock);
    $manager = macos_caddy_manager($connections, $ssh, $guard, $layout, $lock);

    expect(fn () => $manager->converge($node))->toThrow(RuntimeConvergenceException::class);

    $rollback = $ssh->commands[7]->input ?? '';
    expect($rollback)
        ->toContain(
            'expected_user=$(/usr/bin/id -un)',
            'validate_managed_directory "$live_parent"',
            'validate_managed_directory "$plist_parent"',
            'validate_managed_directory "$rollback_parent"',
            'test ! -L "$artifact"',
            'test "$(/usr/bin/stat -f \'%Su\' "$artifact")" = "$expected_user"',
            'artifact_mode=$(/usr/bin/stat -f \'%Lp\' "$artifact")',
            'case "$artifact_mode" in 600|644)',
            'test "$(/usr/bin/plutil -extract Label raw -o - "$rollback/plist.file")" = "$expected_label"',
            'stage_restore_candidate "$path" "$name"',
            'restore_parent=$(/usr/bin/dirname "$path")',
            'validate_managed_directory "$restore_parent"',
            'if ! /bin/mkdir -m 0700 -- "$restore_directory"; then return 1; fi',
            'test "$(/usr/bin/stat -f \'%Lp\' "$restore_directory")" = \'700\'',
            'restore_candidate="$restore_directory/restored"',
            'validate_current_publication "$path" "$name"',
            'validate_restore_candidate "$restore_candidate" "$name"',
            '/bin/mv -h -f -- "$restore_candidate" "$path"',
            'path_matches_snapshot "$path" "$name"',
            'case "$linked_plist_target" in',
            '*) linked_plist="$plist_parent/$linked_plist_target" ;;',
            'test "$(/usr/bin/plutil -extract Label raw -o - "$linked_plist")" = "$expected_label"',
        );

    expect(mb_strpos(haystack: $rollback, needle: 'stage_restore_candidate "$path" "$name"'))
        ->toBeLessThan(mb_strpos(haystack: $rollback, needle: 'validate_current_publication "$path" "$name"'))
        ->and(mb_strpos(haystack: $rollback, needle: 'validate_current_publication "$path" "$name"'))
        ->toBeLessThan(mb_strpos(haystack: $rollback, needle: '/bin/mv -h -f -- "$restore_candidate" "$path"'));
    expect(substr_count(haystack: $rollback, needle: '*) linked_plist="$plist_parent/$linked_plist_target" ;;'))
        ->toBe(2);
    expect(mb_strpos(haystack: $rollback, needle: 'validate_managed_directory "$restore_parent"'))
        ->toBeLessThan(mb_strpos(
            haystack: $rollback,
            needle: 'if ! /bin/mkdir -m 0700 -- "$restore_directory"; then return 1; fi',
        ));
    assert_caddy_bash_syntax($rollback);

    $successfulSsh = new MacOsCaddyTestSsh([
        new CommandResult(0, macos_caddy_adapted_configuration(), '', 1, false),
        new CommandResult(0, "ACQUIRED\n", '', 1, false),
        new CommandResult(0, "501\n", '', 1, false),
        new CommandResult(0, "state = running\n", '', 1, false),
        new CommandResult(0, "CHANGED\n", '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
    ], $lock);
    macos_caddy_manager($connections, $successfulSsh, $guard, $layout, $lock)->converge($node);

    expect($successfulSsh->commands[7]->input ?? '')
        ->toContain(
            'validate_managed_directory "$rollback_parent"',
            'validate_rollback_artifacts',
            'for snapshot_name in configuration plist; do',
            'test "$marker_count" = 1',
            'test ! -L "$artifact"',
        );
    $publish = $successfulSsh->commands[4]->input ?? '';
    $cleanup = $successfulSsh->commands[7]->input ?? '';
    expect($publish)
        ->toContain(
            'rollback_on_error()',
            'validate_rollback_artifacts()',
            'stage_restore_candidate "$path" "$name"',
            '/bin/mv -h -f -- "$restore_candidate" "$path"',
        );
    foreach ([$publish, $rollback, $cleanup] as $recoveryScript) {
        expect($recoveryScript)
            ->toContain(
                'validate_artifact_for_delete() {',
                'missing) test ! -s "$artifact" ;;',
                'test "$(/usr/bin/wc -l < "$artifact" | /usr/bin/tr -d \' \')" = 1',
                'test -n "$(/bin/cat "$artifact")"',
                'validate_artifact_for_delete "$artifact" "$snapshot_name" "$suffix"',
            );
        expect(substr_count(
            haystack: $recoveryScript,
            needle: 'validate_artifact_for_delete "$artifact" "$snapshot_name" "$suffix"',
        ))->toBe(1);
        expect(mb_strpos(
            haystack: $recoveryScript,
            needle: 'validate_artifact_for_delete "$artifact" "$snapshot_name" "$suffix"',
        ))->toBeLessThan(mb_strpos(haystack: $recoveryScript, needle: '/bin/rm -- "$artifact"'));
    }
    assert_caddy_bash_syntax($publish);
    assert_caddy_bash_syntax($cleanup);
});

function assert_caddy_bash_syntax(string $script): void
{
    $process = new SymfonyProcess(['/bin/bash', '-n']);
    $process->setInput($script);

    expect($process->run())
        ->toBe(0)
        ->and($process->getErrorOutput())
        ->toBeEmpty();
}

function macos_caddy_manager(
    MacOsSshConnectionFactory $connections,
    SshExecutor $ssh,
    MacOsSteadyStateCommandGuard $guard,
    MacOsFilesystemLayout $layout,
    AppDevSourceOperationLock $lock,
): MacOsAppDevCaddyManager {
    return new MacOsAppDevCaddyManager(
        new AppDevSiteRepository(new AppDevHostPaths),
        new MacOsAppDevCaddyConfigRenderer($layout),
        new AppDevHostPaths,
        $layout,
        $connections,
        $ssh,
        $guard,
        new MacOsLaunchAgentManager($connections, $ssh, $guard),
        $lock,
    );
}

function macos_caddy_adapted_configuration(): string
{
    return json_encode([
        'admin' => ['disabled' => true],
        'apps' => [
            'http' => [
                'servers' => [
                    'http' => ['listen' => ['10.44.0.9:8080']],
                    'https' => ['listen' => ['10.44.0.9:8443'], 'protocols' => ['h1', 'h2']],
                ],
            ],
        ],
    ], JSON_THROW_ON_ERROR);
}

function macos_caddy_models(): Node
{
    $node = Node::query()->create([
        'name' => 'mini',
        'platform' => 'darwin',
        'architecture' => 'arm64',
        'ssh_user' => 'nckrtl',
        'tld' => 'mini.orbit',
        'status' => LifecycleStatus::Active,
        'public_ssh_host' => '10.44.0.9',
        'wireguard_address' => '10.44.0.9',
    ]);
    $node->roles()->create(['role' => RoleName::AppDev, 'status' => LifecycleStatus::Active]);
    $app = OrbitApp::query()->create([
        'name' => 'Acme',
        'slug' => 'acme',
        'repository_url' => 'git@github.com:acme/site.git',
    ]);
    Instance::query()->create([
        'app_id' => $app->id,
        'node_id' => $node->id,
        'name' => 'dev',
        'environment' => 'development',
        'checkout_path' => '/Users/nckrtl/apps/acme',
        'document_root' => 'public',
        'php_version' => '8.5',
        'hostname' => 'acme.mini.orbit',
        'certificate_mode' => CertificateMode::OrbitCa,
        'status' => LifecycleStatus::Active,
    ]);

    return $node;
}

function macos_caddy_connections(): MacOsSshConnectionFactory
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

final class MacOsCaddyTestLock implements AppDevSourceOperationLock
{
    /** @var list<int> */ public array $nodeIds = [];
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

/** @mago-expect lint:single-class-per-file Test-local SSH fake keeps lock and command order observable. */
final class MacOsCaddyTestSsh implements SshExecutor
{
    /** @var list<RemoteCommand> */ public array $commands = [];

    /** @param list<CommandResult|Throwable> $results */ public function __construct(
        private array $results,
        private MacOsCaddyTestLock $lock,
    ) {}

    public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
    {
        expect($this->lock->held)->toBeTrue();
        $this->commands[] = $command;

        $result = array_shift($this->results) ?? new CommandResult(0, '', '', 1, false);

        if ($result instanceof Throwable) {
            throw $result;
        }

        return $result;
    }
}
