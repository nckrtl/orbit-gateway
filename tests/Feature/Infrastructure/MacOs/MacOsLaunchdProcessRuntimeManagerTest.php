<?php

declare(strict_types=1);

use App\Domain\Nodes\RoleName;
use App\Domain\Processes\DesiredProcessState;
use App\Domain\Processes\ProcessRuntime;
use App\Domain\Processes\ProcessTargetResolver;
use App\Domain\Shared\LifecycleStatus;
use App\Domain\Shared\ResourceOperationException;
use App\Infrastructure\MacOs\MacOsLaunchdProcessRuntimeManager;
use App\Infrastructure\MacOs\MacOsSshConnectionFactory;
use App\Infrastructure\MacOs\MacOsSteadyStateCommandGuard;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Processes\LaunchdProcessRenderer;
use App\Infrastructure\Processes\ProtectedInput;
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
use App\Models\Process;
use Illuminate\Support\Facades\Cache;

it('returns the stable missing-session error before Darwin mutation', function (): void {
    $ssh = new MacOsLaunchdRuntimeTestSsh([
        new CommandResult(0, "501\n", '', 1, false),
        new CommandResult(1, '', 'Could not find domain for user', 1, false),
    ]);
    $manager = new MacOsLaunchdProcessRuntimeManager(
        new ProcessTargetResolver,
        macos_launchd_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new LaunchdProcessRenderer,
    );
    $process = macos_launchd_process();

    expect(fn () => $manager->converge($process))
        ->toThrow(ResourceOperationException::class, 'GUI user session');

    expect($ssh->commands)->toHaveCount(2);
});

it('publishes launchd with protected stdin and exact fixed argv', function (): void {
    $servicePrints = 0;
    $ssh = new MacOsLaunchdRuntimeTestSsh(
        handler: static function (RemoteCommand $command) use (&$servicePrints): CommandResult {
            if ($command->arguments === ['/usr/bin/id', '-u']) {
                return new CommandResult(0, "501\n", '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501']) {
                return new CommandResult(0, 'gui domain', '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501/dev.orbit.process.1.queue']) {
                $servicePrints++;

                return $servicePrints === 1
                    ? new CommandResult(1, '', 'Could not find service', 1, false)
                    : new CommandResult(0, "state = running\npid = 11\n", '', 1, false);
            }

            if (
                $command->arguments === [
                    '/bin/test',
                    '-e',
                    '/Users/nckrtl/Library/LaunchAgents/dev.orbit.process.1.queue.plist',
                ]
            ) {
                return new CommandResult(1, '', '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'bootout', 'gui/501/dev.orbit.process.1.queue']) {
                return new CommandResult(1, '', 'Could not find service', 1, false);
            }

            return new CommandResult(0, '', '', 1, false);
        },
    );
    $manager = new MacOsLaunchdProcessRuntimeManager(
        new ProcessTargetResolver,
        macos_launchd_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new LaunchdProcessRenderer,
        startReadinessAttempts: 1,
    );
    $process = macos_launchd_process();
    $process->update(['desired_state' => DesiredProcessState::Running]);

    $manager->converge($process);

    $publication = array_find(
        $ssh->commands,
        static fn (RemoteCommand $command): bool => in_array(
            'orbit-launchd-publish',
            $command->arguments,
            strict: true,
        ),
    );

    expect($publication)
        ->toBeInstanceOf(RemoteCommand::class)
        ->and(array_slice($publication->arguments, offset: 0, length: 5))
        ->toBe([
            '/bin/bash',
            '-seu',
            '-c',
            $publication->arguments[3],
            'orbit-launchd-publish',
        ])
        ->and($publication->arguments)
        ->toContain(
            '/Users/nckrtl/Library/LaunchAgents/dev.orbit.process.1.queue.plist',
            'dev.orbit.process.1.queue',
        )
        ->and($publication->input)
        ->toBeNull()
        ->and($publication->protectedInput)
        ->toBeInstanceOf(ProtectedInput::class)
        ->and(implode("\n", array_map(
            static fn (RemoteCommand $command): string => implode(' ', $command->arguments),
            $ssh->commands,
        )))
        ->toContain('/usr/bin/id -u')
        ->toContain('/bin/launchctl print gui/501')
        ->toContain('/bin/launchctl kickstart -k gui/501/dev.orbit.process.1.queue')
        ->not->toContain('sudo')
        ->not->toContain('bash -lc');
});

it('validates canonical non-symlink owned paths before protected publication', function (): void {
    $ssh = new MacOsLaunchdRuntimeTestSsh(
        handler: static function (RemoteCommand $command): CommandResult {
            if ($command->arguments === ['/usr/bin/id', '-u']) {
                return new CommandResult(0, "501\n", '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501']) {
                return new CommandResult(0, 'gui domain', '', 1, false);
            }

            if ($command->arguments[0] === '/bin/bash') {
                return new CommandResult(73, '', 'unsafe launchd path', 1, false);
            }

            return new CommandResult(1, '', 'Could not find service', 1, false);
        },
    );
    $manager = new MacOsLaunchdProcessRuntimeManager(
        new ProcessTargetResolver,
        macos_launchd_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new LaunchdProcessRenderer,
    );

    expect(fn () => $manager->converge(macos_launchd_process()))
        ->toThrow(\App\Domain\Processes\ProcessOperationException::class);

    $pathCheck = array_find(
        $ssh->commands,
        static fn (RemoteCommand $command): bool => $command->arguments[0] === '/bin/bash',
    );

    expect($pathCheck)
        ->toBeInstanceOf(RemoteCommand::class)
        ->and($pathCheck->protectedInput)
        ->toBeNull()
        ->and($pathCheck->input)
        ->toBeString()
        ->toContain(
            'test ! -L "$path"',
            'test "$(cd "$path" && /bin/pwd -P)" = "$path"',
            'test "$(/usr/bin/stat -f %Su -- "$path")" = "$expected_user"',
        )
        ->and(array_slice($pathCheck->arguments, offset: 0, length: 5))
        ->toBe([
            '/bin/bash',
            '-seu',
            '--',
            'nckrtl',
            'dev.orbit.process.1.queue',
        ])
        ->and($pathCheck->arguments)
        ->toContain(
            '/Users/nckrtl',
            '/Users/nckrtl/.orbit',
            '/Users/nckrtl/Library/LaunchAgents',
            '/Users/nckrtl/Library/Logs/Orbit/processes',
            '/Users/nckrtl/Library/LaunchAgents/dev.orbit.process.1.queue.plist',
            '/Users/nckrtl/Library/Logs/Orbit/processes/dev.orbit.process.1.queue.stdout.log',
            '/Users/nckrtl/Library/Logs/Orbit/processes/dev.orbit.process.1.queue.stderr.log',
            'nckrtl',
        )
        ->and(array_filter(
            $ssh->commands,
            static fn (RemoteCommand $command): bool => $command->protectedInput instanceof ProtectedInput,
        ))
        ->toBeEmpty();
});

it('fails snapshot on an arbitrary launchctl service probe failure', function (): void {
    $ssh = macos_launchd_runtime_ssh_for_snapshot_failure(
        new CommandResult(1, '', 'Input/output error', 1, false),
        new CommandResult(1, '', 'No such file', 1, false),
    );
    $manager = new MacOsLaunchdProcessRuntimeManager(
        new ProcessTargetResolver,
        macos_launchd_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new LaunchdProcessRenderer,
    );

    expect(fn () => $manager->converge(macos_launchd_process()))
        ->toThrow(\App\Domain\Processes\ProcessOperationException::class);

    expect(array_filter(
        $ssh->commands,
        static fn (RemoteCommand $command): bool => $command->protectedInput instanceof ProtectedInput,
    ))->toBeEmpty();
});

it('fails snapshot on an arbitrary plist read failure instead of treating it as absent', function (): void {
    $ssh = macos_launchd_runtime_ssh_for_snapshot_failure(
        new CommandResult(1, '', 'Could not find service', 1, false),
        new CommandResult(1, '', 'Permission denied', 1, false),
    );
    $manager = new MacOsLaunchdProcessRuntimeManager(
        new ProcessTargetResolver,
        macos_launchd_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new LaunchdProcessRenderer,
    );

    expect(fn () => $manager->converge(macos_launchd_process()))
        ->toThrow(\App\Domain\Processes\ProcessOperationException::class);

    expect(array_filter(
        $ssh->commands,
        static fn (RemoteCommand $command): bool => $command->protectedInput instanceof ProtectedInput,
    ))->toBeEmpty();
});

it('stops start immediately when bootout fails unexpectedly', function (): void {
    $ssh = macos_launchd_runtime_ssh_for_start(
        new CommandResult(1, '', 'Input/output error', 1, false),
        new CommandResult(0, '', '', 1, false),
    );
    $manager = new MacOsLaunchdProcessRuntimeManager(
        new ProcessTargetResolver,
        macos_launchd_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new LaunchdProcessRenderer,
    );

    expect(fn () => $manager->start(macos_launchd_process()))
        ->toThrow(\App\Domain\Processes\ProcessOperationException::class);

    expect(array_map(static fn (RemoteCommand $command): array => $command->arguments, $ssh->commands))
        ->not
        ->toContain([
            '/bin/launchctl',
            'bootstrap',
            'gui/501',
            '/Users/nckrtl/Library/LaunchAgents/dev.orbit.process.1.queue.plist',
        ]);
});

it('stops start immediately when bootstrap fails', function (): void {
    $ssh = macos_launchd_runtime_ssh_for_start(
        new CommandResult(1, '', 'Could not find service', 1, false),
        new CommandResult(1, '', 'Bootstrap failed: 5', 1, false),
    );
    $manager = new MacOsLaunchdProcessRuntimeManager(
        new ProcessTargetResolver,
        macos_launchd_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new LaunchdProcessRenderer,
    );

    expect(fn () => $manager->start(macos_launchd_process()))
        ->toThrow(\App\Domain\Processes\ProcessOperationException::class);

    expect(array_map(static fn (RemoteCommand $command): array => $command->arguments, $ssh->commands))
        ->not
        ->toContain([
            '/bin/launchctl',
            'kickstart',
            '-k',
            'gui/501/dev.orbit.process.1.queue',
        ]);
});

it('does not suppress an unexpected rollback bootout failure', function (): void {
    $ssh = new MacOsLaunchdRuntimeTestSsh(
        handler: static function (RemoteCommand $command): CommandResult {
            if ($command->arguments === ['/usr/bin/id', '-u']) {
                return new CommandResult(0, "501\n", '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501']) {
                return new CommandResult(0, 'gui domain', '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501/dev.orbit.process.1.queue']) {
                return new CommandResult(1, '', 'Could not find service', 1, false);
            }

            if (
                $command->arguments === [
                    '/bin/test',
                    '-e',
                    '/Users/nckrtl/Library/LaunchAgents/dev.orbit.process.1.queue.plist',
                ]
            ) {
                return new CommandResult(1, '', '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'bootout', 'gui/501/dev.orbit.process.1.queue']) {
                return new CommandResult(1, '', 'Input/output error', 1, false);
            }

            if (in_array('orbit-launchd-rollback', $command->arguments, strict: true)) {
                return new CommandResult(1, '', 'rollback bootout failed', 1, false);
            }

            return new CommandResult(0, '', '', 1, false);
        },
    );
    $manager = new MacOsLaunchdProcessRuntimeManager(
        new ProcessTargetResolver,
        macos_launchd_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new LaunchdProcessRenderer,
        startReadinessAttempts: 1,
    );
    $process = macos_launchd_process();
    $process->update(['desired_state' => DesiredProcessState::Running]);

    try {
        $manager->converge($process);
    } catch (\App\Domain\Processes\ProcessOperationException $exception) {
        expect($exception->errorCode)->toBe('process.launchd_recovery_required');

        $rollback = array_find(
            $ssh->commands,
            static fn (RemoteCommand $command): bool => in_array(
                'orbit-launchd-rollback',
                $command->arguments,
                strict: true,
            ),
        );

        expect($rollback)
            ->toBeInstanceOf(RemoteCommand::class)
            ->and($rollback->protectedInput)
            ->toBeNull()
            ->and($rollback->arguments[3])
            ->not->toContain('|| true');

        return;
    }

    $this->fail('Expected launchd rollback recovery to be required.');
});

it('requires a successful launchctl print before restoring a previously stopped service', function (): void {
    $ssh = new MacOsLaunchdRuntimeTestSsh(
        handler: static function (RemoteCommand $command): CommandResult {
            if ($command->arguments === ['/usr/bin/id', '-u']) {
                return new CommandResult(0, "501\n", '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501']) {
                return new CommandResult(0, 'gui domain', '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501/dev.orbit.process.1.queue']) {
                return new CommandResult(1, '', 'Could not find service', 1, false);
            }

            if (
                $command->arguments === [
                    '/bin/test',
                    '-e',
                    '/Users/nckrtl/Library/LaunchAgents/dev.orbit.process.1.queue.plist',
                ]
            ) {
                return new CommandResult(1, '', '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'bootout', 'gui/501/dev.orbit.process.1.queue']) {
                return new CommandResult(1, '', 'Input/output error', 1, false);
            }

            return new CommandResult(0, '', '', 1, false);
        },
    );
    $manager = new MacOsLaunchdProcessRuntimeManager(
        new ProcessTargetResolver,
        macos_launchd_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new LaunchdProcessRenderer,
        startReadinessAttempts: 1,
    );
    $process = macos_launchd_process();
    $process->update(['desired_state' => DesiredProcessState::Running]);

    expect(fn () => $manager->converge($process))
        ->toThrow(\App\Domain\Processes\ProcessOperationException::class);

    $rollback = array_find(
        $ssh->commands,
        static fn (RemoteCommand $command): bool => in_array(
            'orbit-launchd-rollback',
            $command->arguments,
            strict: true,
        ),
    );

    expect($rollback)
        ->toBeInstanceOf(RemoteCommand::class)
        ->and($rollback->arguments[3])
        ->toContain(
            'status=$(/bin/launchctl print "$service")',
            'printf \'%s\\n\' "$status" | /usr/bin/grep',
        )
        ->not->toContain('if /bin/launchctl print "$service" |');
});

it('requires a recognized non-running state before prior-stopped rollback succeeds', function (): void {
    $recognizedStateCheck = <<<'BASH'
        printf '%s\n' "$status" | /usr/bin/grep -Eq '^[[:space:]]*state[[:space:]]*=[[:space:]]*not running[[:space:]]*$'
        BASH;
    $ssh = new MacOsLaunchdRuntimeTestSsh(
        handler: static function (RemoteCommand $command) use ($recognizedStateCheck): CommandResult {
            if ($command->arguments === ['/usr/bin/id', '-u']) {
                return new CommandResult(0, "501\n", '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501']) {
                return new CommandResult(0, 'gui domain', '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501/dev.orbit.process.1.queue']) {
                return new CommandResult(1, '', 'Could not find service', 1, false);
            }

            if (
                $command->arguments === [
                    '/bin/test',
                    '-e',
                    '/Users/nckrtl/Library/LaunchAgents/dev.orbit.process.1.queue.plist',
                ]
            ) {
                return new CommandResult(1, '', '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'bootout', 'gui/501/dev.orbit.process.1.queue']) {
                return new CommandResult(1, '', 'Input/output error', 1, false);
            }

            if (in_array('orbit-launchd-rollback', $command->arguments, strict: true)) {
                return str_contains($command->arguments[3], $recognizedStateCheck)
                    ? new CommandResult(73, '', 'unknown launchd state', 1, false)
                    : new CommandResult(0, '', '', 1, false);
            }

            return new CommandResult(0, '', '', 1, false);
        },
    );
    $manager = new MacOsLaunchdProcessRuntimeManager(
        new ProcessTargetResolver,
        macos_launchd_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new LaunchdProcessRenderer,
        startReadinessAttempts: 1,
    );
    $process = macos_launchd_process();
    $process->update(['desired_state' => DesiredProcessState::Running]);

    try {
        $manager->converge($process);
    } catch (\App\Domain\Processes\ProcessOperationException $exception) {
        $rollback = array_find(
            $ssh->commands,
            static fn (RemoteCommand $command): bool => in_array(
                'orbit-launchd-rollback',
                $command->arguments,
                strict: true,
            ),
        );

        expect($exception->errorCode)
            ->toBe('process.launchd_recovery_required')
            ->and($rollback)
            ->toBeInstanceOf(RemoteCommand::class)
            ->and($rollback->arguments[3])
            ->toContain($recognizedStateCheck);

        return;
    }

    $this->fail('Expected an unknown restored launchd state to require recovery.');
});

it('normalizes a non-process activation exception after restoring the published plist', function (): void {
    $ssh = new MacOsLaunchdRuntimeTestSsh(
        handler: static function (RemoteCommand $command): CommandResult {
            if ($command->arguments === ['/usr/bin/id', '-u']) {
                return new CommandResult(0, "501\n", '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501']) {
                return new CommandResult(0, 'gui domain', '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501/dev.orbit.process.1.queue']) {
                return new CommandResult(1, '', 'Could not find service', 1, false);
            }

            if (
                $command->arguments === [
                    '/bin/test',
                    '-e',
                    '/Users/nckrtl/Library/LaunchAgents/dev.orbit.process.1.queue.plist',
                ]
            ) {
                return new CommandResult(1, '', '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'enable', 'gui/501/dev.orbit.process.1.queue']) {
                throw new RuntimeException('activation transport failed');
            }

            return new CommandResult(0, '', '', 1, false);
        },
    );
    $manager = new MacOsLaunchdProcessRuntimeManager(
        new ProcessTargetResolver,
        macos_launchd_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new LaunchdProcessRenderer,
        startReadinessAttempts: 1,
    );
    $process = macos_launchd_process();
    $process->update(['desired_state' => DesiredProcessState::Running]);

    try {
        $manager->converge($process);
    } catch (Throwable $exception) {
        expect($exception)
            ->toBeInstanceOf(\App\Domain\Processes\ProcessOperationException::class)
            ->and($exception->errorCode)
            ->toBe('process.launchd_converge_failed')
            ->and($exception->step)
            ->toBe('activate-launchd-state')
            ->and($exception->getPrevious())
            ->toBeNull()
            ->and(json_encode([
                'message' => $exception->getMessage(),
                'result' => $exception->result,
                'trace' => $exception->getTrace(),
            ], JSON_THROW_ON_ERROR))
            ->not->toContain('activation transport failed');

        expect(array_any(
            $ssh->commands,
            static fn (RemoteCommand $command): bool => in_array(
                'orbit-launchd-rollback',
                $command->arguments,
                strict: true,
            ),
        ))->toBeTrue();

        return;
    }

    $this->fail('Expected the non-domain activation failure to be normalized.');
});

it('restores the snapshot after an ambiguous thrown publication result', function (): void {
    $publishSentinel = 'publish-transport-diagnostic-sentinel';
    $ssh = macos_launchd_runtime_ssh_for_ambiguous_publish(
        new RuntimeException($publishSentinel),
        new CommandResult(0, '', '', 1, false),
    );
    $manager = new MacOsLaunchdProcessRuntimeManager(
        new ProcessTargetResolver,
        macos_launchd_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new LaunchdProcessRenderer,
    );

    try {
        $manager->converge(macos_launchd_process());
    } catch (Throwable $exception) {
        $rollback = array_find(
            $ssh->commands,
            static fn (RemoteCommand $command): bool => in_array(
                'orbit-launchd-rollback',
                $command->arguments,
                strict: true,
            ),
        );

        expect($exception)
            ->toBeInstanceOf(\App\Domain\Processes\ProcessOperationException::class)
            ->and($exception->step)
            ->toBe('publish-launchd-state')
            ->and($exception->errorCode)
            ->toBe('process.launchd_converge_failed')
            ->and($exception->getPrevious())
            ->toBeNull()
            ->and(json_encode([
                'message' => $exception->getMessage(),
                'result' => $exception->result,
                'trace' => $exception->getTrace(),
            ], JSON_THROW_ON_ERROR))
            ->not
            ->toContain($publishSentinel)
            ->and($rollback)
            ->toBeInstanceOf(RemoteCommand::class)
            ->and(array_slice($rollback->arguments, -3))
            ->toBe(['1', '1', '1']);

        return;
    }

    $this->fail('Expected the ambiguous publication failure to be normalized.');
});

it('requires recovery when ambiguous publication rollback fails', function (): void {
    $publishSentinel = 'publish-transport-diagnostic-sentinel';
    $ssh = macos_launchd_runtime_ssh_for_ambiguous_publish(
        new RuntimeException($publishSentinel),
        new CommandResult(73, '', 'rollback failed', 1, false),
    );
    $manager = new MacOsLaunchdProcessRuntimeManager(
        new ProcessTargetResolver,
        macos_launchd_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new LaunchdProcessRenderer,
    );

    try {
        $manager->converge(macos_launchd_process());
    } catch (Throwable $exception) {
        expect($exception)
            ->toBeInstanceOf(\App\Domain\Processes\ProcessOperationException::class)
            ->and($exception->step)
            ->toBe('restore-launchd-state')
            ->and($exception->errorCode)
            ->toBe('process.launchd_recovery_required')
            ->and($exception->getPrevious())
            ->toBeNull()
            ->and(json_encode([
                'message' => $exception->getMessage(),
                'result' => $exception->result,
                'trace' => $exception->getTrace(),
            ], JSON_THROW_ON_ERROR))
            ->not->toContain($publishSentinel);

        return;
    }

    $this->fail('Expected failed ambiguous-publication rollback to require recovery.');
});

it('restores the snapshot after an unsuccessful publication result', function (): void {
    $sentinel = 'publication-result-secret';
    $ssh = macos_launchd_runtime_ssh_for_ambiguous_publish(
        new CommandResult(255, '', "transport failed: {$sentinel}", 1, false),
        new CommandResult(0, '', '', 1, false),
    );
    $manager = new MacOsLaunchdProcessRuntimeManager(
        new ProcessTargetResolver,
        macos_launchd_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new LaunchdProcessRenderer,
    );
    $process = macos_launchd_process();
    $process->forceFill([
        'runtime_config' => [
            'command' => ['/usr/bin/php', 'artisan', 'queue:work'],
            'environment' => ['PUBLISH_SECRET' => $sentinel],
        ],
    ])->save();

    try {
        $manager->converge($process);
    } catch (\App\Domain\Processes\ProcessOperationException $exception) {
        $rollback = array_find(
            $ssh->commands,
            static fn (RemoteCommand $command): bool => in_array(
                'orbit-launchd-rollback',
                $command->arguments,
                strict: true,
            ),
        );
        $result = json_encode($exception->result, JSON_THROW_ON_ERROR);

        expect($rollback)
            ->toBeInstanceOf(RemoteCommand::class)
            ->and($exception->step)
            ->toBe('publish')
            ->and($exception->errorCode)
            ->toBe('process.launchd_converge_failed')
            ->and($result)
            ->not
            ->toContain($sentinel)
            ->toContain('[REDACTED]');

        return;
    }

    $this->fail('Expected the unsuccessful publication result to fail after snapshot restore.');
});

it('requires recovery when unsuccessful publication result rollback fails', function (): void {
    $ssh = macos_launchd_runtime_ssh_for_ambiguous_publish(
        new CommandResult(255, '', 'transport failed', 1, false),
        new CommandResult(73, '', 'rollback failed', 1, false),
    );
    $manager = new MacOsLaunchdProcessRuntimeManager(
        new ProcessTargetResolver,
        macos_launchd_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new LaunchdProcessRenderer,
    );

    try {
        $manager->converge(macos_launchd_process());
    } catch (\App\Domain\Processes\ProcessOperationException $exception) {
        expect($exception->step)
            ->toBe('restore-launchd-state')
            ->and($exception->errorCode)
            ->toBe('process.launchd_recovery_required');

        return;
    }

    $this->fail('Expected failed publication-result rollback to require recovery.');
});

it('does not rollback a deterministic pre-publication script failure', function (): void {
    $ssh = macos_launchd_runtime_ssh_for_ambiguous_publish(
        new CommandResult(73, '', 'unsafe path', 1, false),
        new CommandResult(0, '', '', 1, false),
    );
    $manager = new MacOsLaunchdProcessRuntimeManager(
        new ProcessTargetResolver,
        macos_launchd_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new LaunchdProcessRenderer,
    );

    try {
        $manager->converge(macos_launchd_process());
    } catch (\App\Domain\Processes\ProcessOperationException $exception) {
        expect($exception->step)
            ->toBe('publish')
            ->and($exception->errorCode)
            ->toBe('process.launchd_converge_failed')
            ->and(array_any(
                $ssh->commands,
                static fn (RemoteCommand $command): bool => in_array(
                    'orbit-launchd-rollback',
                    $command->arguments,
                    strict: true,
                ),
            ))
            ->toBeFalse();

        return;
    }

    $this->fail('Expected deterministic publication failure.');
});

it('does not rollback a local render validation failure', function (): void {
    $ssh = macos_launchd_runtime_ssh_for_ambiguous_publish(
        new RuntimeException('publish must not run'),
        new CommandResult(0, '', '', 1, false),
    );
    $manager = new MacOsLaunchdProcessRuntimeManager(
        new ProcessTargetResolver,
        macos_launchd_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new LaunchdProcessRenderer,
    );
    $process = macos_launchd_process();
    $process->forceFill([
        'runtime_config' => [
            'command' => ['/usr/bin/php', 'artisan', 'queue:work'],
            'environment' => ['INVALID_XML' => "before\u{FFFE}after"],
        ],
    ])->save();

    expect(fn () => $manager->converge($process))->toThrow(InvalidArgumentException::class);

    expect(array_filter(
        $ssh->commands,
        static fn (RemoteCommand $command): bool => (
            in_array('orbit-launchd-publish', $command->arguments, strict: true)
            || in_array('orbit-launchd-rollback', $command->arguments, strict: true)
        ),
    ))->toBeEmpty();
});

it('maps a thrown rollback attempt to recovery-required without diagnostics', function (): void {
    $rollbackSentinel = 'rollback-transport-diagnostic-sentinel';
    $ssh = new MacOsLaunchdRuntimeTestSsh(
        handler: static function (RemoteCommand $command) use ($rollbackSentinel): CommandResult {
            if ($command->arguments === ['/usr/bin/id', '-u']) {
                return new CommandResult(0, "501\n", '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501']) {
                return new CommandResult(0, 'gui domain', '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501/dev.orbit.process.1.queue']) {
                return new CommandResult(1, '', 'Could not find service', 1, false);
            }

            if (
                $command->arguments === [
                    '/bin/test',
                    '-e',
                    '/Users/nckrtl/Library/LaunchAgents/dev.orbit.process.1.queue.plist',
                ]
            ) {
                return new CommandResult(1, '', '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'enable', 'gui/501/dev.orbit.process.1.queue']) {
                throw new RuntimeException('activation transport failed');
            }

            if (in_array('orbit-launchd-rollback', $command->arguments, strict: true)) {
                throw new RuntimeException($rollbackSentinel);
            }

            return new CommandResult(0, '', '', 1, false);
        },
    );
    $manager = new MacOsLaunchdProcessRuntimeManager(
        new ProcessTargetResolver,
        macos_launchd_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new LaunchdProcessRenderer,
        startReadinessAttempts: 1,
    );
    $process = macos_launchd_process();
    $process->update(['desired_state' => DesiredProcessState::Running]);

    try {
        $manager->converge($process);
    } catch (\App\Domain\Processes\ProcessOperationException $exception) {
        expect($exception->errorCode)
            ->toBe('process.launchd_recovery_required')
            ->and(json_encode([
                'message' => $exception->getMessage(),
                'result' => $exception->result,
                'previous' => $exception->getPrevious()?->getMessage(),
                'trace' => $exception->getTrace(),
            ], JSON_THROW_ON_ERROR))
            ->not->toContain($rollbackSentinel);

        return;
    }

    $this->fail('Expected the thrown rollback attempt to require recovery.');
});

it('maps a thrown cleanup command to diagnostic-free recovery-required', function (): void {
    $cleanupSentinel = 'cleanup-transport-diagnostic-sentinel';
    $ssh = new MacOsLaunchdRuntimeTestSsh(
        handler: static function (RemoteCommand $command) use ($cleanupSentinel): CommandResult {
            if ($command->arguments === ['/usr/bin/id', '-u']) {
                return new CommandResult(0, "501\n", '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501']) {
                return new CommandResult(0, 'gui domain', '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501/dev.orbit.process.1.queue']) {
                return new CommandResult(1, '', 'Could not find service', 1, false);
            }

            if (
                $command->arguments === [
                    '/bin/test',
                    '-e',
                    '/Users/nckrtl/Library/LaunchAgents/dev.orbit.process.1.queue.plist',
                ]
            ) {
                return new CommandResult(1, '', '', 1, false);
            }

            if (in_array('orbit-launchd-cleanup', $command->arguments, strict: true)) {
                throw new RuntimeException($cleanupSentinel);
            }

            return new CommandResult(0, '', '', 1, false);
        },
    );
    $manager = new MacOsLaunchdProcessRuntimeManager(
        new ProcessTargetResolver,
        macos_launchd_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new LaunchdProcessRenderer,
    );

    try {
        $manager->converge(macos_launchd_process());
    } catch (Throwable $exception) {
        expect($exception)
            ->toBeInstanceOf(\App\Domain\Processes\ProcessOperationException::class)
            ->and($exception->step)
            ->toBe('finalize-launchd-state')
            ->and($exception->errorCode)
            ->toBe('process.launchd_recovery_required')
            ->and($exception->getPrevious())
            ->toBeNull()
            ->and(json_encode([
                'message' => $exception->getMessage(),
                'result' => $exception->result,
                'trace' => $exception->getTrace(),
            ], JSON_THROW_ON_ERROR))
            ->not->toContain($cleanupSentinel);

        return;
    }

    $this->fail('Expected the thrown cleanup command to require recovery.');
});

it('pins one SSH connection for all commands in one launchd operation', function (): void {
    $scanner = new MacOsLaunchdCountingHostKeyScanner;
    $ssh = new MacOsLaunchdRuntimeTestSsh(
        handler: static function (RemoteCommand $command): CommandResult {
            if ($command->arguments === ['/usr/bin/id', '-u']) {
                return new CommandResult(0, "501\n", '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501']) {
                return new CommandResult(0, 'gui domain', '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501/dev.orbit.process.1.queue']) {
                return new CommandResult(0, "state = running\npid = 11\n", '', 1, false);
            }

            return new CommandResult(0, '', '', 1, false);
        },
    );
    $manager = new MacOsLaunchdProcessRuntimeManager(
        new ProcessTargetResolver,
        macos_launchd_connections($scanner),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new LaunchdProcessRenderer,
    );

    expect($manager->status(macos_launchd_process()))
        ->toBe('running')
        ->and($scanner->scans)
        ->toBe(1);
});

it('maps the legacy-proven native launchd not-running state to stopped', function (): void {
    $ssh = new MacOsLaunchdRuntimeTestSsh(
        handler: static function (RemoteCommand $command): CommandResult {
            if ($command->arguments === ['/usr/bin/id', '-u']) {
                return new CommandResult(0, "501\n", '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501']) {
                return new CommandResult(0, 'gui domain', '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501/dev.orbit.process.1.queue']) {
                return new CommandResult(0, "state = not running\npid = 0\n", '', 1, false);
            }

            return new CommandResult(0, '', '', 1, false);
        },
    );
    $manager = new MacOsLaunchdProcessRuntimeManager(
        new ProcessTargetResolver,
        macos_launchd_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new LaunchdProcessRenderer,
    );

    expect($manager->status(macos_launchd_process()))->toBe('stopped');
});

it('rejects launchd not-found lookalikes with extra diagnostics', function (): void {
    $ssh = new MacOsLaunchdRuntimeTestSsh(
        handler: static function (RemoteCommand $command): CommandResult {
            if ($command->arguments === ['/usr/bin/id', '-u']) {
                return new CommandResult(0, "501\n", '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501']) {
                return new CommandResult(0, 'gui domain', '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501/dev.orbit.process.1.queue']) {
                return new CommandResult(1, '', 'Could not find service after Input/output error', 1, false);
            }

            return new CommandResult(0, '', '', 1, false);
        },
    );
    $manager = new MacOsLaunchdProcessRuntimeManager(
        new ProcessTargetResolver,
        macos_launchd_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new LaunchdProcessRenderer,
    );

    expect(fn () => $manager->status(macos_launchd_process()))
        ->toThrow(\App\Domain\Processes\ProcessOperationException::class);
});

it('accepts only the canonical launchd label and uid not-found message', function (string $diagnostic): void {
    $ssh = new MacOsLaunchdRuntimeTestSsh(
        handler: static function (RemoteCommand $command) use ($diagnostic): CommandResult {
            if ($command->arguments === ['/usr/bin/id', '-u']) {
                return new CommandResult(0, "501\n", '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501']) {
                return new CommandResult(0, 'gui domain', '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501/dev.orbit.process.1.queue']) {
                return new CommandResult(1, '', $diagnostic, 1, false);
            }

            return new CommandResult(0, '', '', 1, false);
        },
    );
    $manager = new MacOsLaunchdProcessRuntimeManager(
        new ProcessTargetResolver,
        macos_launchd_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new LaunchdProcessRenderer,
    );

    expect($manager->status(macos_launchd_process()))->toBe('absent');
})->with([
    'canonical' => 'Could not find service "dev.orbit.process.1.queue" in domain for user gui: 501',
    'canonical after Bad request' => "Bad request.\nCould not find service \"dev.orbit.process.1.queue\" in domain for user gui: 501",
]);

it('uses the exact node and process lock and releases it after a failed mutation', function (): void {
    $ssh = new MacOsLaunchdRuntimeTestSsh([
        new CommandResult(0, "501\n", '', 1, false),
        new CommandResult(1, '', 'Could not find domain for user', 1, false),
    ]);
    $manager = new MacOsLaunchdProcessRuntimeManager(
        new ProcessTargetResolver,
        macos_launchd_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new LaunchdProcessRenderer,
    );
    $process = macos_launchd_process();
    $nodeId = Instance::query()->findOrFail($process->owner_id)->node_id;
    $lockKey = "orbit:process-runtime:{$nodeId}:{$process->id}";
    $contendingLock = Cache::lock($lockKey, 60);

    expect($contendingLock->get())->toBeTrue();

    try {
        expect(fn () => $manager->converge($process))
            ->toThrow(\App\Domain\Processes\ProcessOperationException::class, 'runtime is busy');

        expect($ssh->commands)->toBeEmpty();
    } finally {
        $contendingLock->release();
    }

    expect(fn () => $manager->converge($process))
        ->toThrow(ResourceOperationException::class, 'GUI user session');

    $releasedLock = Cache::lock($lockKey, 60);

    try {
        expect($releasedLock->get())->toBeTrue();
    } finally {
        $releasedLock->release();
    }
});

it('retries only native-not-found readiness before observing launchd running', function (): void {
    $servicePrints = 0;
    $ssh = new MacOsLaunchdRuntimeTestSsh(
        handler: static function (RemoteCommand $command) use (&$servicePrints): CommandResult {
            if ($command->arguments === ['/usr/bin/id', '-u']) {
                return new CommandResult(0, "501\n", '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501']) {
                return new CommandResult(0, 'gui domain', '', 1, false);
            }

            if (
                $command->arguments === [
                    '/bin/test',
                    '-e',
                    '/Users/nckrtl/Library/LaunchAgents/dev.orbit.process.1.queue.plist',
                ]
            ) {
                return new CommandResult(0, '', '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'bootout', 'gui/501/dev.orbit.process.1.queue']) {
                return new CommandResult(1, '', 'Could not find service', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501/dev.orbit.process.1.queue']) {
                $servicePrints++;

                return match ($servicePrints) {
                    1 => new CommandResult(0, "state = not running\npid = 0\n", '', 1, false),
                    2 => new CommandResult(1, '', 'Could not find service', 1, false),
                    default => new CommandResult(0, "state = running\npid = 11\n", '', 1, false),
                };
            }

            return new CommandResult(0, '', '', 1, false);
        },
    );
    $manager = new MacOsLaunchdProcessRuntimeManager(
        new ProcessTargetResolver,
        macos_launchd_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new LaunchdProcessRenderer,
        startReadinessAttempts: 2,
        startReadinessPollMicroseconds: 0,
    );

    $manager->start(macos_launchd_process());

    $commands = array_map(static fn (RemoteCommand $command): array => $command->arguments, $ssh->commands);

    $servicePrints = array_keys(array_filter(
        $commands,
        static fn (array $arguments): bool => $arguments === [
            '/bin/launchctl',
            'print',
            'gui/501/dev.orbit.process.1.queue',
        ],
    ));

    expect($servicePrints)
        ->toHaveCount(3)
        ->and(array_search(
            ['/bin/launchctl', 'kickstart', '-k', 'gui/501/dev.orbit.process.1.queue'],
            $commands,
            strict: true,
        ))
        ->toBeLessThan($servicePrints[1]);
});

it('leaves an already-running launchd service untouched on public start', function (): void {
    $ssh = new MacOsLaunchdRuntimeTestSsh(
        handler: static function (RemoteCommand $command): CommandResult {
            if ($command->arguments === ['/usr/bin/id', '-u']) {
                return new CommandResult(0, "501\n", '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501']) {
                return new CommandResult(0, 'gui domain', '', 1, false);
            }

            if (
                $command->arguments === [
                    '/bin/test',
                    '-e',
                    '/Users/nckrtl/Library/LaunchAgents/dev.orbit.process.1.queue.plist',
                ]
            ) {
                return new CommandResult(0, '', '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501/dev.orbit.process.1.queue']) {
                return new CommandResult(0, "state = running\npid = 11\n", '', 1, false);
            }

            return new CommandResult(0, '', '', 1, false);
        },
    );
    $manager = new MacOsLaunchdProcessRuntimeManager(
        new ProcessTargetResolver,
        macos_launchd_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new LaunchdProcessRenderer,
        startReadinessAttempts: 1,
    );

    $manager->start(macos_launchd_process());

    $commands = array_map(static fn (RemoteCommand $command): array => $command->arguments, $ssh->commands);

    expect($commands)
        ->toContain(['/bin/launchctl', 'enable', 'gui/501/dev.orbit.process.1.queue'])
        ->not->toContain(['/bin/launchctl', 'bootout', 'gui/501/dev.orbit.process.1.queue'])
        ->not->toContain([
            '/bin/launchctl',
            'bootstrap',
            'gui/501',
            '/Users/nckrtl/Library/LaunchAgents/dev.orbit.process.1.queue.plist',
        ])
        ->not->toContain(['/bin/launchctl', 'kickstart', '-k', 'gui/501/dev.orbit.process.1.queue']);
});

it('treats exact native bootout absence as idempotent on public stop', function (): void {
    $ssh = macos_launchd_runtime_ssh_for_stop(
        new CommandResult(
            1,
            '',
            'Could not find service "dev.orbit.process.1.queue" in domain for user gui: 501',
            1,
            false,
        ),
    );
    $manager = new MacOsLaunchdProcessRuntimeManager(
        new ProcessTargetResolver,
        macos_launchd_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new LaunchdProcessRenderer,
    );
    $exception = null;

    try {
        $manager->stop(macos_launchd_process());
    } catch (Throwable $throwable) {
        $exception = $throwable;
    }

    expect($exception)
        ->toBeNull()
        ->and(array_map(static fn (RemoteCommand $command): array => $command->arguments, $ssh->commands))
        ->toContain(
            ['/bin/launchctl', 'disable', 'gui/501/dev.orbit.process.1.queue'],
            ['/bin/launchctl', 'bootout', 'gui/501/dev.orbit.process.1.queue'],
        );
});

it('rejects a bootout absence lookalike on public stop', function (): void {
    $ssh = macos_launchd_runtime_ssh_for_stop(
        new CommandResult(
            1,
            '',
            "Could not find service \"dev.orbit.process.1.queue\" in domain for user gui: 501\nconnection reset",
            1,
            false,
        ),
    );
    $manager = new MacOsLaunchdProcessRuntimeManager(
        new ProcessTargetResolver,
        macos_launchd_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new LaunchdProcessRenderer,
    );

    expect(fn () => $manager->stop(macos_launchd_process()))
        ->toThrow(\App\Domain\Processes\ProcessOperationException::class, 'runtime operation failed');
});

it('uses the legacy-proven bounded launchd readiness window with a zero-delay test seam', function (): void {
    $reflection = new ReflectionClass(MacOsLaunchdProcessRuntimeManager::class);
    $constructor = $reflection->getConstructor();
    $parameters = collect($constructor?->getParameters())
        ->keyBy(
            static fn (ReflectionParameter $parameter): string => $parameter->name,
        );
    $timeout = $reflection->getReflectionConstant('START_READINESS_TIMEOUT_SECONDS');
    $poll = $reflection->getReflectionConstant('START_READINESS_POLL_MICROSECONDS');

    expect($timeout instanceof ReflectionClassConstant ? $timeout->getValue() : null)
        ->toBe(15.0)
        ->and($poll instanceof ReflectionClassConstant ? $poll->getValue() : null)
        ->toBe(500_000)
        ->and($parameters->get('startReadinessAttempts')?->getDefaultValue())
        ->toBeNull()
        ->and($parameters->get('startReadinessTimeoutSeconds')?->getDefaultValue())
        ->toBe(15.0)
        ->and($parameters->get('startReadinessPollMicroseconds')?->getDefaultValue())
        ->toBe(500_000);
});

it('clamps launchd logs to the fixed tail maximum with exact argv', function (): void {
    $ssh = new MacOsLaunchdRuntimeTestSsh(
        handler: static function (RemoteCommand $command): CommandResult {
            if ($command->arguments[0] === '/usr/bin/tail') {
                return new CommandResult(0, "worker output\n", '', 1, false);
            }

            return new CommandResult(0, '', '', 1, false);
        },
    );
    $manager = new MacOsLaunchdProcessRuntimeManager(
        new ProcessTargetResolver,
        macos_launchd_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new LaunchdProcessRenderer,
    );

    expect($manager->logs(macos_launchd_process(), PHP_INT_MAX))->toBe("worker output\n");

    $tail = array_find(
        $ssh->commands,
        static fn (RemoteCommand $command): bool => $command->arguments[0] === '/usr/bin/tail',
    );

    expect($tail)
        ->toBeInstanceOf(RemoteCommand::class)
        ->and($tail->arguments)
        ->toBe([
            '/usr/bin/tail',
            '-n',
            '1000',
            '--',
            '/Users/nckrtl/Library/Logs/Orbit/processes/dev.orbit.process.1.queue.stdout.log',
            '/Users/nckrtl/Library/Logs/Orbit/processes/dev.orbit.process.1.queue.stderr.log',
        ]);
});

it('keeps configured environment values out of launchd failures and app-owned traces', function (): void {
    $sentinel = 'launchd-lifecycle-boundary-secret';
    $ssh = macos_launchd_runtime_ssh_for_start(
        new CommandResult(1, '', 'Could not find service', 1, false),
        new CommandResult(1, '', "remote failed: {$sentinel}", 1, false),
    );
    $manager = new MacOsLaunchdProcessRuntimeManager(
        new ProcessTargetResolver,
        macos_launchd_connections(),
        $ssh,
        new MacOsSteadyStateCommandGuard,
        new LaunchdProcessRenderer,
    );
    $process = macos_launchd_process();
    $process->forceFill([
        'runtime_config' => [
            'command' => ['/usr/bin/php', 'artisan', 'queue:work'],
            'environment' => ['TRACE_VALUE' => $sentinel],
        ],
    ])->save();

    try {
        $manager->start($process);
    } catch (\App\Domain\Processes\ProcessOperationException $exception) {
        $appTrace = array_values(array_filter(
            $exception->getTrace(),
            static fn (array $frame): bool => (
                is_string($frame['file'] ?? null) && str_starts_with($frame['file'], base_path('app').'/')
            ),
        ));
        $result = json_encode($exception->result, JSON_THROW_ON_ERROR);

        expect(array_column($appTrace, 'function'))
            ->toContain('executeSuccessfully', 'startUnlocked', 'withRuntimeLock')
            ->and(json_encode($appTrace, JSON_THROW_ON_ERROR))
            ->not->toContain($sentinel)->and($result)
            ->not->toContain($sentinel)->toContain('[REDACTED]');

        return;
    }

    $this->fail('Expected launchd start to fail.');
});

it('marks every launchd runtime process boundary sensitive', function (string $method): void {
    $parameters = new ReflectionMethod(MacOsLaunchdProcessRuntimeManager::class, $method)->getParameters();
    $process = array_find(
        $parameters,
        static fn (ReflectionParameter $parameter): bool => $parameter->name === 'process',
    );

    expect($process)
        ->toBeInstanceOf(ReflectionParameter::class)
        ->and($process->getAttributes(SensitiveParameter::class))
        ->toHaveCount(1);
})->with([
    'converge',
    'start',
    'stop',
    'restart',
    'remove',
    'status',
    'logs',
    'userSession',
    'snapshot',
    'rollback',
    'restoreSnapshot',
    'cleanup',
    'startUnlocked',
    'stopUnlockedWhileToleratingMissing',
    'stopLaunchd',
    'withRuntimeLock',
    'assertSafePaths',
    'assertPlistPresent',
    'plistExists',
    'execute',
    'executeSuccessfully',
    'fail',
    'redactedResult',
    'paths',
]);

it('marks raw launchd diagnostic and command parameters sensitive', function (string $method, string $parameter): void {
    $parameters = new ReflectionMethod(MacOsLaunchdProcessRuntimeManager::class, $method)->getParameters();
    $sensitive = array_find(
        $parameters,
        static fn (ReflectionParameter $candidate): bool => $candidate->name === $parameter,
    );

    expect($sensitive)
        ->toBeInstanceOf(ReflectionParameter::class)
        ->and($sensitive->getAttributes(SensitiveParameter::class))
        ->toHaveCount(1);
})->with([
    'fail result' => ['fail', 'result'],
    'redacted result' => ['redactedResult', 'result'],
    'not-found result' => ['isLaunchdNotFound', 'result'],
    'remote command' => ['execute', 'command'],
]);

it('revalidates exact owned non-symlink parents inside every launchd mutation script', function (
    string $constant,
    array $parents,
): void {
    $reflection = new ReflectionClass(MacOsLaunchdProcessRuntimeManager::class);
    $script = $reflection->getReflectionConstant($constant)?->getValue();

    expect($script)
        ->toBeString()
        ->toContain(
            'validate_directory() {',
            'test ! -L "$path"',
            'test "$(cd "$path" && /bin/pwd -P)" = "$path"',
            'test "$(/usr/bin/stat -f %Su -- "$path")" = "$expected_user"',
            ...$parents,
        );
})->with([
    'rollback LaunchAgents parent' => ['ROLLBACK_SCRIPT', ['validate_directory "$directory"']],
    'cleanup LaunchAgents parent' => ['CLEANUP_SCRIPT', ['validate_directory "$directory"']],
    'remove LaunchAgents and log parents' => [
        'REMOVE_SCRIPT',
        [
            'validate_directory "$directory"',
            'validate_directory "${stdout%/*}"',
            'validate_directory "${stderr%/*}"',
        ],
    ],
]);

it('rejects pre-existing launchd candidate and backup collisions before publication', function (): void {
    $script = new ReflectionClass(MacOsLaunchdProcessRuntimeManager::class)
        ->getReflectionConstant('PUBLISH_SCRIPT')
        ?->getValue();

    expect($script)
        ->toBeString()
        ->toContain(
            'candidate_created=0',
            'if test "$candidate_created" = 1 && test -e "$candidate"; then',
            'test ! -e "$candidate" || exit 75',
            'test ! -e "$backup" || exit 75',
        )
        ->not->toContain('if test -e "$candidate"; then /bin/rm -f -- "$candidate"; fi');

    $collision = strpos($script, needle: 'test ! -e "$candidate" || exit 75');
    $ownership = strpos($script, needle: 'candidate_created=1');
    $write = strpos($script, needle: '/bin/cat > "$candidate"');

    expect($collision)
        ->toBeInt()
        ->and($ownership)
        ->toBeInt()
        ->toBeGreaterThan($collision)
        ->and($write)
        ->toBeInt()
        ->toBeGreaterThan($ownership);
});

it('revalidates exact plist labels inside every mutating launchd script', function (
    string $constant,
    array $calls,
    array $orderedPairs,
): void {
    $script = new ReflectionClass(MacOsLaunchdProcessRuntimeManager::class)
        ->getReflectionConstant($constant)
        ?->getValue();

    expect($script)
        ->toBeString()
        ->toContain(
            'validate_label_if_present() {',
            'observed_label=$(/usr/bin/plutil -extract Label raw -o - -- "$path")',
            'test "$observed_label" = "$label" || fail',
            ...$calls,
        );

    foreach ($orderedPairs as [$validation, $mutation]) {
        $mutationPosition = strpos($script, $mutation);
        $validationPosition = is_int($mutationPosition)
            ? strrpos(substr($script, offset: 0, length: $mutationPosition), $validation)
            : false;

        expect($mutationPosition)
            ->toBeInt()
            ->and($validationPosition)
            ->toBeInt()
            ->toBeLessThan($mutationPosition);
    }
})->with([
    'publish validates live, candidate, and backup plists' => [
        'PUBLISH_SCRIPT',
        [
            'validate_label_if_present "$plist"',
            'validate_label_if_present "$candidate"',
            'validate_label_if_present "$backup"',
        ],
        [
            ['validate_label_if_present "$candidate"', '/bin/rm -f -- "$candidate"'],
            ['validate_label_if_present "$backup"',    '/bin/rm -f -- "$backup"'],
            ['validate_label_if_present "$plist"',     '/bin/cp -p "$plist" "$backup"'],
            ['validate_label_if_present "$candidate"', '/bin/mv -f -- "$candidate" "$plist"'],
        ],
    ],
    'rollback validates live, candidate, and backup plists' => [
        'ROLLBACK_SCRIPT',
        [
            'validate_label_if_present "$plist"',
            'validate_label_if_present "$candidate"',
            'validate_label_if_present "$backup"',
        ],
        [
            ['validate_label_if_present "$backup"',    '/bin/mv -f -- "$backup" "$plist"'],
            ['validate_label_if_present "$plist"',     '/bin/rm -f -- "$plist"'],
            ['validate_label_if_present "$backup"',    '/bin/rm -f -- "$backup"'],
            ['validate_label_if_present "$candidate"', '/bin/rm -f -- "$candidate"'],
        ],
    ],
    'cleanup validates every rollback artifact' => [
        'CLEANUP_SCRIPT',
        ['validate_label_if_present "$path"'],
        [['validate_label_if_present "$path"', '/bin/rm -f -- "$path"']],
    ],
    'remove validates live, candidate, and backup plists' => [
        'REMOVE_SCRIPT',
        [
            'validate_label_if_present "$plist"',
            'validate_label_if_present "$candidate"',
            'validate_label_if_present "$backup"',
        ],
        [
            [
                'validate_label_if_present "$plist"',
                '/bin/rm -f -- "$plist" "$stdout" "$stderr" "$candidate" "$backup"',
            ],
            [
                'validate_label_if_present "$candidate"',
                '/bin/rm -f -- "$plist" "$stdout" "$stderr" "$candidate" "$backup"',
            ],
            [
                'validate_label_if_present "$backup"',
                '/bin/rm -f -- "$plist" "$stdout" "$stderr" "$candidate" "$backup"',
            ],
        ],
    ],
]);

function macos_launchd_runtime_ssh_for_snapshot_failure(
    CommandResult $state,
    CommandResult $contents,
): MacOsLaunchdRuntimeTestSsh {
    return new MacOsLaunchdRuntimeTestSsh(
        handler: static function (RemoteCommand $command) use ($state, $contents): CommandResult {
            if ($command->arguments === ['/usr/bin/id', '-u']) {
                return new CommandResult(0, "501\n", '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501']) {
                return new CommandResult(0, 'gui domain', '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501/dev.orbit.process.1.queue']) {
                return $state;
            }

            if (
                $command->arguments === [
                    '/bin/test',
                    '-e',
                    '/Users/nckrtl/Library/LaunchAgents/dev.orbit.process.1.queue.plist',
                ]
            ) {
                return $contents;
            }

            return new CommandResult(0, '', '', 1, false);
        },
    );
}

function macos_launchd_runtime_ssh_for_start(
    CommandResult $bootout,
    CommandResult $bootstrap,
): MacOsLaunchdRuntimeTestSsh {
    return new MacOsLaunchdRuntimeTestSsh(
        handler: static function (RemoteCommand $command) use ($bootout, $bootstrap): CommandResult {
            if ($command->arguments === ['/usr/bin/id', '-u']) {
                return new CommandResult(0, "501\n", '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501']) {
                return new CommandResult(0, 'gui domain', '', 1, false);
            }

            if (
                $command->arguments === [
                    '/bin/test',
                    '-e',
                    '/Users/nckrtl/Library/LaunchAgents/dev.orbit.process.1.queue.plist',
                ]
            ) {
                return new CommandResult(0, '', '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501/dev.orbit.process.1.queue']) {
                return new CommandResult(0, "state = not running\npid = 0\n", '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'bootout', 'gui/501/dev.orbit.process.1.queue']) {
                return $bootout;
            }

            if (
                $command->arguments === [
                    '/bin/launchctl',
                    'bootstrap',
                    'gui/501',
                    '/Users/nckrtl/Library/LaunchAgents/dev.orbit.process.1.queue.plist',
                ]
            ) {
                return $bootstrap;
            }

            return new CommandResult(0, '', '', 1, false);
        },
    );
}

function macos_launchd_runtime_ssh_for_stop(CommandResult $bootout): MacOsLaunchdRuntimeTestSsh
{
    return new MacOsLaunchdRuntimeTestSsh(
        handler: static function (RemoteCommand $command) use ($bootout): CommandResult {
            if ($command->arguments === ['/usr/bin/id', '-u']) {
                return new CommandResult(0, "501\n", '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501']) {
                return new CommandResult(0, 'gui domain', '', 1, false);
            }

            if (
                $command->arguments === [
                    '/bin/test',
                    '-e',
                    '/Users/nckrtl/Library/LaunchAgents/dev.orbit.process.1.queue.plist',
                ]
            ) {
                return new CommandResult(0, '', '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'bootout', 'gui/501/dev.orbit.process.1.queue']) {
                return $bootout;
            }

            return new CommandResult(0, '', '', 1, false);
        },
    );
}

function macos_launchd_runtime_ssh_for_ambiguous_publish(
    CommandResult|Throwable $publication,
    CommandResult $rollback,
): MacOsLaunchdRuntimeTestSsh {
    return new MacOsLaunchdRuntimeTestSsh(
        handler: static function (RemoteCommand $command) use ($publication, $rollback): CommandResult {
            if ($command->arguments === ['/usr/bin/id', '-u']) {
                return new CommandResult(0, "501\n", '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501']) {
                return new CommandResult(0, 'gui domain', '', 1, false);
            }

            if ($command->arguments === ['/bin/launchctl', 'print', 'gui/501/dev.orbit.process.1.queue']) {
                return new CommandResult(0, "state = running\npid = 11\n", '', 1, false);
            }

            if (
                $command->arguments === [
                    '/bin/test',
                    '-e',
                    '/Users/nckrtl/Library/LaunchAgents/dev.orbit.process.1.queue.plist',
                ]
            ) {
                return new CommandResult(0, '', '', 1, false);
            }

            if (in_array('orbit-launchd-publish', $command->arguments, strict: true)) {
                if ($publication instanceof Throwable) {
                    throw $publication;
                }

                return $publication;
            }

            if (in_array('orbit-launchd-rollback', $command->arguments, strict: true)) {
                return $rollback;
            }

            return new CommandResult(0, '', '', 1, false);
        },
    );
}

function macos_launchd_process(): Process
{
    $node = Node::query()->create([
        'name' => 'mac-app-dev',
        'status' => LifecycleStatus::Active,
        'platform' => 'darwin',
        'public_ssh_host' => '192.0.2.20',
        'public_ssh_port' => 22,
        'ssh_user' => 'nckrtl',
        'wireguard_address' => '10.44.0.9',
    ]);
    $node->roles()->create(['role' => RoleName::AppDev, 'status' => LifecycleStatus::Active]);
    $app = OrbitApp::query()->create([
        'name' => 'Docs',
        'slug' => 'docs',
        'repository_url' => 'git@example.test:docs.git',
    ]);
    $instance = Instance::query()->create([
        'app_id' => $app->id,
        'node_id' => $node->id,
        'name' => 'main',
        'environment' => 'development',
        'checkout_path' => '/Users/nckrtl/apps/docs',
        'document_root' => 'public',
        'php_version' => '8.5',
        'hostname' => 'docs.app-dev.orbit',
        'certificate_mode' => 'orbit-ca',
        'status' => LifecycleStatus::Active,
    ]);

    return Process::query()->create([
        'owner_type' => Instance::class,
        'owner_id' => $instance->id,
        'name' => 'queue',
        'runtime' => ProcessRuntime::Launchd,
        'working_directory' => '/Users/nckrtl/apps/docs',
        'runtime_config' => [
            'command' => ['/usr/bin/php', 'artisan', 'queue:work'],
            'environment' => ['APP_ENV' => 'local'],
        ],
        'restart_policy' => 'always',
        'desired_state' => 'stopped',
        'status' => LifecycleStatus::Active,
    ]);
}

function macos_launchd_connections(?HostKeyScanner $hostKeyScanner = null): MacOsSshConnectionFactory
{
    return new MacOsSshConnectionFactory(
        $hostKeyScanner
        ?? new class implements HostKeyScanner {
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

final class MacOsLaunchdCountingHostKeyScanner implements HostKeyScanner
{
    public int $scans = 0;

    public function scan(string $host, int $port): HostKey
    {
        $this->scans++;

        return new HostKey('ssh-ed25519', 'AAAAC3', 'SHA256:test');
    }
}

/** @mago-expect lint:single-class-per-file Test-local fakes keep exact launchd SSH traffic visible. */
final class MacOsLaunchdRuntimeTestSsh implements SshExecutor
{
    /** @var list<RemoteCommand> */
    public array $commands = [];

    /** @param list<CommandResult> $results */
    public function __construct(
        private array $results = [],
        private readonly ?Closure $handler = null,
    ) {}

    public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
    {
        $this->commands[] = $command;

        if ($this->handler instanceof Closure) {
            return ($this->handler)($command);
        }

        return array_shift($this->results) ?? new CommandResult(0, '', '', 1, false);
    }
}
