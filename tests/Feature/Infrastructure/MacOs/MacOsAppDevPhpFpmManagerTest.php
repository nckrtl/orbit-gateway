<?php

declare(strict_types=1);

use App\Domain\AppDev\AppDevHostPaths;
use App\Domain\AppDev\AppDevSourceOperationLock;
use App\Domain\Instances\CertificateMode;
use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Infrastructure\AppDev\AppDevSiteRepository;
use App\Infrastructure\MacOs\MacOsAppDevPhpFpmConfigRenderer;
use App\Infrastructure\MacOs\MacOsAppDevPhpFpmManager;
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
use Illuminate\Support\Facades\DB;
use Symfony\Component\Process\Process as SymfonyProcess;

/** @mago-expect lint:halstead This interaction test asserts the complete atomic publication and launchd order. */
it('installs only a missing Homebrew formula and publishes the validated live user FPM master', function (
    string $version,
    string $formula,
    string $formulaRoot,
): void {
    $node = macos_php_models($version);
    $lock = new MacOsPhpTestLock;
    $queriesOutsideLock = [];
    DB::listen(function ($query) use ($lock, &$queriesOutsideLock): void {
        if (! $lock->held && preg_match('/(?:instances|workspaces)/', $query->sql) === 1) {
            $queriesOutsideLock[] = $query->sql;
        }
    });
    $ssh = new MacOsPhpTestSsh([
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, "ACQUIRED\n", '', 1, false),
        new CommandResult(1, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, "{$version}.12\n", '', 1, false),
        new CommandResult(0, "501\n", '', 1, false),
        new CommandResult(0, "state = running\n", '', 1, false),
        new CommandResult(0, "CHANGED\n", '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
    ], $lock);
    $connections = macos_php_connections();
    $guard = new MacOsSteadyStateCommandGuard;
    $layout = new MacOsFilesystemLayout;
    $manager = new MacOsAppDevPhpFpmManager(
        sites: new AppDevSiteRepository(new AppDevHostPaths),
        renderer: new MacOsAppDevPhpFpmConfigRenderer($layout),
        paths: new AppDevHostPaths,
        layout: $layout,
        connections: $connections,
        ssh: $ssh,
        guard: $guard,
        launchAgents: new MacOsLaunchAgentManager($connections, $ssh, $guard),
        lock: $lock,
    );

    $manager->converge($node);

    $commands = array_map(static fn (RemoteCommand $command): array => $command->arguments, $ssh->commands);
    $publish = $ssh->commands[7]->input ?? '';
    preg_match_all("/printf '%s' '([^']+)'/", $publish, $encodedPayloads);
    $publishedPlist = base64_decode($encodedPayloads[1][1] ?? '', strict: true);
    expect($lock->nodeIds)
        ->toBe([$node->id])
        ->and($queriesOutsideLock)
        ->toBeEmpty()
        ->and($commands[0][0] ?? null)
        ->toBe('/bin/bash')
        ->and(array_slice($commands[2], offset: 5))
        ->toBe(['/opt/homebrew/bin/brew', 'list', '--versions', $formula])
        ->and(array_slice($commands[3], offset: 5))
        ->toBe(['/opt/homebrew/bin/brew', 'install', $formula])
        ->and(array_slice($commands[4], offset: 5))
        ->toBe(["{$formulaRoot}/bin/php-config", '--version'])
        ->and($commands[8])
        ->toContain('/bin/launchctl', 'bootout')
        ->and($commands[9])
        ->toContain('/bin/launchctl', 'bootstrap')
        ->and($commands[7])
        ->toContain(
            '/Users/nckrtl/.orbit/run/php/php-fpm-'.$version.'.lock',
            '/Users/nckrtl/.orbit/php/'.$version.'/php-fpm.conf',
        )
        ->and($publish)
        ->toContain(
            '"$php_fpm" -t -y "$candidate_configuration"',
            'snapshot_path "$live_configuration" configuration',
            'snapshot_path "$plist" plist',
            'mv -h -f -- "$configuration_link" "$live_configuration"',
        )
        ->not->toContain('sudo')
        ->not->toContain('upgrade')
        ->not->toContain('user =')
        ->not->toContain('group =')
        ->not->toContain('opcache')->and($publishedPlist)->toContain(
            '<key>PATH</key><string>/opt/homebrew/bin:/opt/homebrew/sbin:/usr/bin:/bin:/usr/sbin:/sbin</string>',
        )->and(mb_strpos(
            haystack: $publish,
            needle: '"$php_fpm" -t -y "$candidate_configuration"',
        ))->toBeLessThan(mb_strpos(
            haystack: $publish,
            needle: 'mv -h -f -- "$configuration_link" "$live_configuration"',
        ))->and(implode("\n", array_map(
            static fn (RemoteCommand $command): string => implode(' ', $command->arguments).($command->input ?? ''),
            $ssh->commands,
        )))
        ->not->toContain('sudo')
        ->not->toContain('brew upgrade');
})->with([
    'default PHP' => ['8.5', 'php', '/opt/homebrew/opt/php'],
    'versioned PHP' => ['8.4', 'php@8.4', '/opt/homebrew/opt/php@8.4'],
]);

it('keeps a discovered managed version healthy after its final site is removed', function (): void {
    $node = macos_php_models('8.4');
    Instance::query()->delete();
    $lock = new MacOsPhpTestLock;
    $ssh = new MacOsPhpTestSsh([
        new CommandResult(0, "8.4\n", '', 1, false),
        new CommandResult(0, "ACQUIRED\n", '', 1, false),
        new CommandResult(0, "php@8.4 8.4.12\n", '', 1, false),
        new CommandResult(0, "8.4.12\n", '', 1, false),
        new CommandResult(0, "501\n", '', 1, false),
        new CommandResult(1, '', 'Could not find service', 1, false),
        new CommandResult(0, "CHANGED\n", '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
    ], $lock);
    $connections = macos_php_connections();
    $guard = new MacOsSteadyStateCommandGuard;
    $layout = new MacOsFilesystemLayout;
    $manager = new MacOsAppDevPhpFpmManager(
        new AppDevSiteRepository(new AppDevHostPaths),
        new MacOsAppDevPhpFpmConfigRenderer($layout),
        new AppDevHostPaths,
        $layout,
        $connections,
        $ssh,
        $guard,
        new MacOsLaunchAgentManager($connections, $ssh, $guard),
        $lock,
    );

    $manager->converge($node);

    $publication = $ssh->commands[6]->input ?? '';
    preg_match_all("/printf '%s' '([^']+)'/", $publication, $encodedPayloads);
    $configuration = base64_decode($encodedPayloads[1][0] ?? '', strict: true);
    expect($configuration)
        ->toContain('[orbit-health]', '/Users/nckrtl/.orbit/run/php/health-8.4.sock')
        ->not->toContain('[instance-')
        ->not->toContain('[workspace-');
});

it('rejects every unsupported stored site PHP version before SSH discovery', function (): void {
    $node = macos_php_models('9.9');
    $lock = new MacOsPhpTestLock;
    $ssh = new MacOsPhpTestSsh([], $lock);
    $connections = macos_php_connections();
    $guard = new MacOsSteadyStateCommandGuard;
    $manager = macos_php_manager($connections, $ssh, $guard, new MacOsFilesystemLayout, $lock);

    expect(fn () => $manager->converge($node))
        ->toThrow(\App\Domain\AppDev\RuntimeConvergenceException::class);
    expect($ssh->commands)->toBeEmpty();
});

it('fences Homebrew discovery installation and php-config with the live PHP lease', function (): void {
    $node = macos_php_models('8.5');
    $lock = new MacOsPhpTestLock;
    $ssh = new MacOsPhpTestSsh([
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, "ACQUIRED\n", '', 1, false),
        new CommandResult(1, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, "8.5.12\n", '', 1, false),
        new CommandResult(0, "501\n", '', 1, false),
        new CommandResult(0, "state = running\n", '', 1, false),
        new CommandResult(0, "UNCHANGED\n", '', 1, false),
        new CommandResult(0, '', '', 1, false),
    ], $lock);
    $manager = macos_php_manager(
        macos_php_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new MacOsFilesystemLayout,
        $lock,
    );

    $manager->converge($node);

    $expectedCommands = [
        ['/opt/homebrew/bin/brew', 'list', '--versions', 'php'],
        ['/opt/homebrew/bin/brew', 'install', 'php'],
        ['/opt/homebrew/opt/php/bin/php-config', '--version'],
    ];

    foreach ([2, 3, 4] as $offset => $commandIndex) {
        $command = $ssh->commands[$commandIndex];
        expect(array_slice($command->arguments, offset: 5))
            ->toBe($expectedCommands[$offset])
            ->and($command->arguments)
            ->toContain('/Users/nckrtl/.orbit/run/php/php-fpm-8.5.lock')
            ->and($command->input)
            ->toContain(
                'test "$(cd "$lock_path" && pwd -P)" = "$lock_path"',
                'test "$current_token" = "$token"',
                'kill -0 "$keeper_pid" 2>/dev/null',
                'orbit-lease-keeper $token $lock_path',
                'exec "$@"',
            )
            ->not->toContain('sudo');
    }
});

it('fails before PHP mutation when a runtime or LaunchAgents ancestor is a symlink', function (): void {
    $node = macos_php_models('8.5');
    $lock = new MacOsPhpTestLock;
    $ssh = new MacOsPhpTestSsh([
        new CommandResult(0, '', '', 1, false),
        new CommandResult(1, '', 'ancestor symlink', 1, false),
    ], $lock);
    $connections = macos_php_connections();
    $guard = new MacOsSteadyStateCommandGuard;
    $manager = macos_php_manager($connections, $ssh, $guard, new MacOsFilesystemLayout, $lock);

    expect(fn () => $manager->converge($node))
        ->toThrow(\App\Domain\AppDev\RuntimeConvergenceException::class);

    $script = $ssh->commands[1]->input ?? '';
    expect($ssh->commands)
        ->toHaveCount(2)
        ->and($script)
        ->toContain(
            '"$home/.orbit"',
            '"$home/.orbit/run"',
            '"$home/.orbit/run/php"',
            '"$home/.orbit/php/$version"',
            '"$home/Library/LaunchAgents"',
            'if [ -L "$managed_directory" ]; then exit 1; fi',
        );
});

it('holds the exact target PHP lease across snapshot publication activation cleanup and release', function (): void {
    $node = macos_php_models('8.5');
    $lock = new MacOsPhpTestLock;
    $ssh = new MacOsPhpTestSsh([
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, "ACQUIRED\n", '', 1, false),
        new CommandResult(0, 'php 8.5.12', '', 1, false),
        new CommandResult(0, '8.5.12', '', 1, false),
        new CommandResult(0, "501\n", '', 1, false),
        new CommandResult(0, "state = running\n", '', 1, false),
        new CommandResult(0, "CHANGED\n", '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
    ], $lock);
    $connections = macos_php_connections();
    $guard = new MacOsSteadyStateCommandGuard;
    $layout = new MacOsFilesystemLayout;
    $manager = macos_php_manager($connections, $ssh, $guard, $layout, $lock);

    $manager->converge($node);

    expect($ssh->commands)
        ->toHaveCount(11)
        ->and($ssh->commands[1]->arguments)
        ->toContain('/Users/nckrtl/.orbit/run/php/php-fpm-8.5.lock')
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
            needle: 'for managed_directory in "$home/.orbit/php"',
        ))->and($ssh->commands[4]->arguments)->toContain(
            '/Users/nckrtl/.orbit/run/php/php-fpm-8.5.lock',
        )->and($ssh->commands[4]->input)->toContain(
            'test "$current_token" = "$token"',
            'kill -0 "$keeper_pid"',
            'orbit-lease-keeper $token $lock_path',
            'exec "$@"',
        )->and($ssh->commands[6]->input)->toContain(
            'test "$current_token" = "$token"',
            'for managed_directory in "$php_root" "$php_root/versions" "$rollback_parent" "$plist_parent"',
            'test ! -L "$managed_directory"',
        )->and($ssh->commands[10]->input)->toContain('rmdir -- "$lock_path"');
});

it('rejects a competing PHP writer before formula or launchd mutation', function (): void {
    $node = macos_php_models('8.5');
    $lock = new MacOsPhpTestLock;
    $ssh = new MacOsPhpTestSsh([
        new CommandResult(0, '', '', 1, false),
        new CommandResult(75, '', 'lock held', 1, false),
    ], $lock);
    $connections = macos_php_connections();
    $guard = new MacOsSteadyStateCommandGuard;
    $layout = new MacOsFilesystemLayout;
    $manager = macos_php_manager($connections, $ssh, $guard, $layout, $lock);

    expect(fn () => $manager->converge($node))
        ->toThrow(\App\Domain\AppDev\RuntimeConvergenceException::class);
    expect($ssh->commands)
        ->toHaveCount(2)
        ->and($ssh->commands[1]->arguments)
        ->toContain('/Users/nckrtl/.orbit/run/php/php-fpm-8.5.lock')
        ->and($ssh->commands[1]->input)
        ->toContain(
            'if kill -0 "$previous_keeper_pid" 2>/dev/null; then',
            'exit 75',
            'mv -h -- "$lock_path" "$stale_lock"',
        )
        ->not->toContain('now - previous_acquired_at')->and(implode(' ', $ssh->commands[1]->arguments))
        ->not->toContain('brew')
        ->not->toContain('launchctl');
});

it('preserves the PHP rollback failure when lease release also fails', function (): void {
    $node = macos_php_models('8.5');
    $lock = new MacOsPhpTestLock;
    $connections = macos_php_connections();
    $guard = new MacOsSteadyStateCommandGuard;
    $layout = new MacOsFilesystemLayout;
    $contendedSsh = new MacOsPhpTestSsh([
        new CommandResult(0, '', '', 1, false),
        new CommandResult(75, '', 'lock held', 1, false),
    ], $lock);
    $contended = macos_php_manager($connections, $contendedSsh, $guard, $layout, $lock);
    expect(fn () => $contended->converge($node))->toThrow(\App\Domain\AppDev\RuntimeConvergenceException::class);

    $rollbackSsh = new MacOsPhpTestSsh([
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, "ACQUIRED\n", '', 1, false),
        new CommandResult(0, 'php 8.5.12', '', 1, false),
        new CommandResult(0, '8.5.12', '', 1, false),
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
    $rollback = macos_php_manager($connections, $rollbackSsh, $guard, $layout, $lock);

    try {
        $rollback->converge($node);
        $this->fail('Expected the PHP-FPM rollback to fail.');
    } catch (\App\Domain\AppDev\RuntimeConvergenceException $exception) {
        expect($exception->step)
            ->toBe('php-fpm-rollback')
            ->and($exception->errorCode)
            ->toBe('app-dev.php_fpm_rollback_failed');
    }
});

it('can retry PHP aggregate convergence after a successful rollback', function (): void {
    $node = macos_php_models('8.5');
    $lock = new MacOsPhpTestLock;
    $connections = macos_php_connections();
    $guard = new MacOsSteadyStateCommandGuard;
    $layout = new MacOsFilesystemLayout;
    $ssh = new MacOsPhpTestSsh([
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, "ACQUIRED\n", '', 1, false),
        new CommandResult(0, 'php 8.5.12', '', 1, false),
        new CommandResult(0, '8.5.12', '', 1, false),
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
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, "ACQUIRED\n", '', 1, false),
        new CommandResult(0, 'php 8.5.12', '', 1, false),
        new CommandResult(0, '8.5.12', '', 1, false),
        new CommandResult(0, "501\n", '', 1, false),
        new CommandResult(0, 'state = running', '', 1, false),
        new CommandResult(0, "CHANGED\n", '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
    ], $lock);
    $manager = macos_php_manager($connections, $ssh, $guard, $layout, $lock);

    expect(fn () => $manager->converge($node))->toThrow(\App\Domain\AppDev\RuntimeConvergenceException::class);
    $manager->converge($node);

    expect($lock->nodeIds)->toBe([$node->id, $node->id])->and($ssh->commands)->toHaveCount(25);
});

it('restores PHP-FPM state after ambiguous exit 255 and thrown publication failures', function (CommandResult|Throwable $failure): void {
    $node = macos_php_models('8.5');
    $lock = new MacOsPhpTestLock;
    $connections = macos_php_connections();
    $guard = new MacOsSteadyStateCommandGuard;
    $layout = new MacOsFilesystemLayout;
    $ssh = new MacOsPhpTestSsh([
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, "ACQUIRED\n", '', 1, false),
        new CommandResult(0, 'php 8.5.12', '', 1, false),
        new CommandResult(0, '8.5.12', '', 1, false),
        new CommandResult(0, "501\n", '', 1, false),
        new CommandResult(0, 'state = running', '', 1, false),
        $failure,
        new CommandResult(0, '', '', 1, false),
        new CommandResult(1, '', 'Could not find service', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
    ], $lock);
    $manager = macos_php_manager($connections, $ssh, $guard, $layout, $lock);

    try {
        $manager->converge($node);
        $this->fail('Expected the ambiguous PHP-FPM publication to fail.');
    } catch (\App\Domain\AppDev\RuntimeConvergenceException $exception) {
        expect($exception->step)
            ->toBe('php-fpm-config')
            ->and($exception->errorCode)
            ->toBe('app-dev.php_fpm_config_failed')
            ->and($exception->getMessage())
            ->not->toContain('publication transport sentinel');
    }

    expect($ssh->commands[7]->input ?? '')
        ->toContain('restore_path "$live_configuration" configuration');
})->with([
    'exit 255 result' => [new CommandResult(255, '', 'transport outcome unknown', 1, false)],
    'thrown transport failure' => [new RuntimeException('publication transport sentinel')],
]);

it('does not start a second PHP-FPM rollback for a deterministic publication failure', function (): void {
    $node = macos_php_models('8.5');
    $lock = new MacOsPhpTestLock;
    $connections = macos_php_connections();
    $guard = new MacOsSteadyStateCommandGuard;
    $layout = new MacOsFilesystemLayout;
    $ssh = new MacOsPhpTestSsh([
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, "ACQUIRED\n", '', 1, false),
        new CommandResult(0, 'php 8.5.12', '', 1, false),
        new CommandResult(0, '8.5.12', '', 1, false),
        new CommandResult(0, "501\n", '', 1, false),
        new CommandResult(0, 'state = running', '', 1, false),
        new CommandResult(73, '', 'deterministic validation failure', 1, false),
        new CommandResult(0, '', '', 1, false),
    ], $lock);

    expect(fn () => macos_php_manager($connections, $ssh, $guard, $layout, $lock)->converge($node))
        ->toThrow(\App\Domain\AppDev\RuntimeConvergenceException::class);
    expect($ssh->commands)
        ->toHaveCount(8)
        ->and($ssh->commands[7]->input ?? '')
        ->toContain('rmdir -- "$lock_path"')
        ->not->toContain('restore_path "$live_configuration" configuration');
});

/** @mago-expect lint:halstead Exact recovery-script assertions keep all immediate mutation gates together. */
it('revalidates PHP-FPM rollback and cleanup parents artifacts ownership modes and plist label', function (): void {
    $node = macos_php_models('8.5');
    $lock = new MacOsPhpTestLock;
    $connections = macos_php_connections();
    $guard = new MacOsSteadyStateCommandGuard;
    $layout = new MacOsFilesystemLayout;
    $ssh = new MacOsPhpTestSsh([
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, "ACQUIRED\n", '', 1, false),
        new CommandResult(0, 'php 8.5.12', '', 1, false),
        new CommandResult(0, '8.5.12', '', 1, false),
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
    ], $lock);
    $manager = macos_php_manager($connections, $ssh, $guard, $layout, $lock);

    expect(fn () => $manager->converge($node))
        ->toThrow(\App\Domain\AppDev\RuntimeConvergenceException::class);

    expect($ssh->commands[9]->input ?? '')
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

    $rollback = $ssh->commands[9]->input ?? '';
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
    assert_php_bash_syntax($rollback);

    $successfulSsh = new MacOsPhpTestSsh([
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, "ACQUIRED\n", '', 1, false),
        new CommandResult(0, 'php 8.5.12', '', 1, false),
        new CommandResult(0, '8.5.12', '', 1, false),
        new CommandResult(0, "501\n", '', 1, false),
        new CommandResult(0, 'state = running', '', 1, false),
        new CommandResult(0, "CHANGED\n", '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
        new CommandResult(0, '', '', 1, false),
    ], $lock);
    macos_php_manager($connections, $successfulSsh, $guard, $layout, $lock)->converge($node);

    expect($successfulSsh->commands[9]->input ?? '')
        ->toContain(
            'validate_managed_directory "$rollback_parent"',
            'for snapshot_name in configuration plist; do',
            'test "$marker_count" = 1',
            'validate_rollback_artifacts',
        );
    $publish = $successfulSsh->commands[6]->input ?? '';
    $cleanup = $successfulSsh->commands[9]->input ?? '';
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
    assert_php_bash_syntax($publish);
    assert_php_bash_syntax($cleanup);
});

function assert_php_bash_syntax(string $script): void
{
    $process = new SymfonyProcess(['/bin/bash', '-n']);
    $process->setInput($script);

    expect($process->run())
        ->toBe(0)
        ->and($process->getErrorOutput())
        ->toBeEmpty();
}

function macos_php_manager(
    MacOsSshConnectionFactory $connections,
    SshExecutor $ssh,
    MacOsSteadyStateCommandGuard $guard,
    MacOsFilesystemLayout $layout,
    AppDevSourceOperationLock $lock,
): MacOsAppDevPhpFpmManager {
    return new MacOsAppDevPhpFpmManager(
        new AppDevSiteRepository(new AppDevHostPaths),
        new MacOsAppDevPhpFpmConfigRenderer($layout),
        new AppDevHostPaths,
        $layout,
        $connections,
        $ssh,
        $guard,
        new MacOsLaunchAgentManager($connections, $ssh, $guard),
        $lock,
    );
}

function macos_php_models(string $version): Node
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
        'php_version' => $version,
        'hostname' => 'acme.mini.orbit',
        'certificate_mode' => CertificateMode::OrbitCa,
        'status' => LifecycleStatus::Active,
    ]);

    return $node;
}

function macos_php_connections(): MacOsSshConnectionFactory
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

final class MacOsPhpTestLock implements AppDevSourceOperationLock
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

/** @mago-expect lint:single-class-per-file Test-local SSH fake keeps lock and command order observable. */
final class MacOsPhpTestSsh implements SshExecutor
{
    /** @var list<RemoteCommand> */
    public array $commands = [];

    /** @param list<CommandResult|Throwable> $results */
    public function __construct(
        private array $results,
        private MacOsPhpTestLock $lock,
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
