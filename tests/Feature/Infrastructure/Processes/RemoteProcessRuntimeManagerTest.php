<?php

declare(strict_types=1);

use App\Domain\Processes\ProcessOperationException;
use App\Domain\Processes\ProcessRuntime;
use App\Domain\Processes\ProcessTargetResolver;
use App\Domain\Shared\LifecycleStatus;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Processes\DockerProcessRenderer;
use App\Infrastructure\Processes\NativeProcessRunner;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Processes\ProcessRunner;
use App\Infrastructure\Processes\ProtectedInput;
use App\Infrastructure\Processes\RemoteProcessRuntimeManager;
use App\Infrastructure\Processes\SystemdProcessRenderer;
use App\Infrastructure\Ssh\KnownHostsStore;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshConnection;
use App\Infrastructure\Ssh\SshExecutor;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Models\App as OrbitApp;
use App\Models\Instance;
use App\Models\Node;
use App\Models\Process;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Facades\Cache;

beforeEach(function (): void {
    $this->ssh = new ProcessRuntimeFakeSshExecutor;
    $this->manager = new RemoteProcessRuntimeManager(
        targets: new ProcessTargetResolver,
        ssh: $this->ssh,
        keys: new ProcessRuntimeFakeSshKeyProvider,
        knownHosts: new ProcessRuntimeFakeKnownHostsStore,
        systemd: new SystemdProcessRenderer,
        docker: new DockerProcessRenderer,
    );
    $node = Node::query()->create([
        'name' => 'app-dev',
        'status' => LifecycleStatus::Active,
        'platform' => 'linux',
        'public_ssh_host' => '192.0.2.20',
        'public_ssh_port' => 22,
        'ssh_user' => 'orbit',
        'wireguard_address' => '10.44.0.3',
    ]);
    $node->roles()->create(['role' => 'app-dev', 'status' => LifecycleStatus::Active]);
    $orbitApp = OrbitApp::query()->create([
        'name' => 'Docs',
        'slug' => 'docs',
        'repository_url' => 'git@example.test:docs.git',
    ]);
    $this->instance = Instance::query()->create([
        'app_id' => $orbitApp->id,
        'node_id' => $node->id,
        'name' => 'main',
        'environment' => 'development',
        'checkout_path' => '/home/orbit/apps/docs',
        'document_root' => 'public',
        'php_version' => '8.5',
        'hostname' => 'docs.app-dev.orbit',
        'certificate_mode' => 'orbit-ca',
        'status' => LifecycleStatus::Active,
    ]);
});

it('installs and manages a systemd process through fixed SSH argv', function (): void {
    $process = runtime_manager_systemd_process($this->instance);
    $unit = 'orbit-process-'.$process->id.'-queue.service';
    $path = "/etc/systemd/system/{$unit}";
    $candidate = "/etc/orbit/systemd-candidates/{$unit}";
    $ownedUnit = "[Unit]\nX-Orbit-Process-ID={$process->id}\n";
    $this->ssh->responses = [
        process_runtime_result(1),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(stdout: $ownedUnit),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(stdout: $ownedUnit),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(stdout: $ownedUnit),
        process_runtime_result(stdout: "line one\nline two\n"),
        process_runtime_result(),
        process_runtime_result(stdout: $ownedUnit),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
    ];

    $this->manager->converge($process);
    $this->manager->start($process);
    $this->manager->stop($process);
    $logs = $this->manager->logs($process, 50);
    $this->manager->remove($process);

    expect($this->ssh->connections)
        ->each(
            fn ($connection) => $connection
                ->host->toBe('10.44.0.3')
                ->user->toBe('orbit')
                ->identityFile->toBe('/orbit/ssh/id_ed25519')
                ->knownHostsFile->toBe('/orbit/ssh/known_hosts'),
        )
        ->and(array_map(
            static fn (RemoteCommand $command): array => $command->arguments,
            $this->ssh->commands,
        ))
        ->toBe([
            ['sudo', 'test', '-e', $path],
            ['sudo', 'install', '-d', '-m', '0755', '/etc/orbit/systemd-candidates'],
            ['sudo', 'install', '-m', '0644', '/dev/stdin', $candidate],
            ['sudo', 'systemd-analyze', 'verify', $candidate],
            ['sudo', 'mv', '--', $candidate, $path],
            ['sudo', 'systemctl', 'daemon-reload'],
            ['sudo', 'systemctl', 'disable', '--now', $unit],
            ['sudo', 'test', '-e', $path],
            ['sudo', 'cat', '--', $path],
            ['sudo', 'systemctl', 'enable', '--now', $unit],
            ['sudo', 'test', '-e', $path],
            ['sudo', 'cat', '--', $path],
            ['sudo', 'systemctl', 'disable', '--now', $unit],
            ['sudo', 'test', '-e', $path],
            ['sudo', 'cat', '--', $path],
            ['sudo', 'journalctl', '--unit', $unit, '--lines', '50', '--no-pager', '--output', 'short-iso'],
            ['sudo', 'test', '-e', $path],
            ['sudo', 'cat', '--', $path],
            ['sudo', 'systemctl', 'disable', '--now', $unit],
            ['sudo', 'rm', '-f', '--', $path],
            ['sudo', 'systemctl', 'daemon-reload'],
        ])
        ->and($this->ssh->commands[2]->input)
        ->toContain("X-Orbit-Process-ID={$process->id}")
        ->and($logs)
        ->toBe("line one\nline two\n");
});

it('refuses to overwrite a systemd unit that is not owned by the process', function (): void {
    $process = runtime_manager_systemd_process($this->instance);
    $this->ssh->responses = [
        process_runtime_result(),
        process_runtime_result(stdout: "[Unit]\nX-Orbit-Process-ID={$process->id}0\nDescription=Personal service\n"),
    ];

    expect(fn () => $this->manager->converge($process))
        ->toThrow(ProcessOperationException::class, 'not owned by this process');

    expect($this->ssh->commands)->toHaveCount(2);
});

it('keeps the live systemd unit untouched when candidate validation fails', function (): void {
    $process = runtime_manager_systemd_process($this->instance);
    $unit = "orbit-process-{$process->id}-queue.service";
    $candidate = "/etc/orbit/systemd-candidates/{$unit}";
    $this->ssh->responses = [
        process_runtime_result(1),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(1, stderr: 'Executable path is not absolute'),
        process_runtime_result(),
    ];

    expect(fn () => $this->manager->converge($process))
        ->toThrow(ProcessOperationException::class, 'candidate validation');

    expect(array_map(
        static fn (RemoteCommand $command): array => $command->arguments,
        $this->ssh->commands,
    ))->toBe([
        ['sudo', 'test', '-e', "/etc/systemd/system/{$unit}"],
        ['sudo', 'install', '-d', '-m', '0755', '/etc/orbit/systemd-candidates'],
        ['sudo', 'install', '-m', '0644', '/dev/stdin', $candidate],
        ['sudo', 'systemd-analyze', 'verify', $candidate],
        ['sudo', 'rm', '-f', '--', $candidate],
    ]);
});

it('restores the previous Orbit-owned systemd unit when activation fails', function (): void {
    $process = runtime_manager_systemd_process($this->instance);
    $unit = "orbit-process-{$process->id}-queue.service";
    $path = "/etc/systemd/system/{$unit}";
    $candidate = "/etc/orbit/systemd-candidates/{$unit}";
    $backup = "/etc/orbit/systemd-candidates/.{$unit}.backup";
    $previous = "[Unit]\nX-Orbit-Process-ID={$process->id}\nDescription=Previous\n";
    $this->ssh->responses = [
        process_runtime_result(),
        process_runtime_result(stdout: $previous),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(1, stderr: 'daemon reload failed'),
        process_runtime_result(),
        process_runtime_result(),
    ];

    expect(fn () => $this->manager->converge($process))
        ->toThrow(ProcessOperationException::class, 'activation failed');

    expect(array_map(
        static fn (RemoteCommand $command): array => $command->arguments,
        $this->ssh->commands,
    ))->toBe([
        ['sudo', 'test', '-e', $path],
        ['sudo', 'cat', '--', $path],
        ['sudo', 'install', '-d', '-m', '0755', '/etc/orbit/systemd-candidates'],
        ['sudo', 'install', '-m', '0644', '/dev/stdin', $candidate],
        ['sudo', 'systemd-analyze', 'verify', $candidate],
        ['sudo', 'cp', '--preserve=mode,ownership,timestamps', '--', $path, $backup],
        ['sudo', 'mv', '--', $candidate, $path],
        ['sudo', 'systemctl', 'daemon-reload'],
        ['sudo', 'mv', '--', $backup, $path],
        ['sudo', 'systemctl', 'daemon-reload'],
    ]);
});

it('keeps the systemd backup until a desired-running replacement restarts successfully', function (): void {
    $process = runtime_manager_systemd_process($this->instance);
    $process->update(['desired_state' => 'running']);
    $unit = "orbit-process-{$process->id}-queue.service";
    $path = "/etc/systemd/system/{$unit}";
    $candidate = "/etc/orbit/systemd-candidates/{$unit}";
    $backup = "/etc/orbit/systemd-candidates/.{$unit}.backup";
    $previous = "[Unit]\nX-Orbit-Process-ID={$process->id}\nDescription=Previous\n";
    $this->ssh->responses = [
        process_runtime_result(),
        process_runtime_result(stdout: $previous),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(1, stderr: 'replacement restart failed'),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
    ];

    expect(fn () => $this->manager->converge($process))
        ->toThrow(ProcessOperationException::class, 'previous unit was restored');

    expect(array_map(
        static fn (RemoteCommand $command): array => $command->arguments,
        $this->ssh->commands,
    ))->toBe([
        ['sudo', 'test', '-e', $path],
        ['sudo', 'cat', '--', $path],
        ['sudo', 'install', '-d', '-m', '0755', '/etc/orbit/systemd-candidates'],
        ['sudo', 'install', '-m', '0644', '/dev/stdin', $candidate],
        ['sudo', 'systemd-analyze', 'verify', $candidate],
        ['sudo', 'cp', '--preserve=mode,ownership,timestamps', '--', $path, $backup],
        ['sudo', 'mv', '--', $candidate, $path],
        ['sudo', 'systemctl', 'daemon-reload'],
        ['sudo', 'systemctl', 'enable', $unit],
        ['sudo', 'systemctl', 'restart', $unit],
        ['sudo', 'systemctl', 'disable', '--now', $unit],
        ['sudo', 'mv', '--', $backup, $path],
        ['sudo', 'systemctl', 'daemon-reload'],
        ['sudo', 'systemctl', 'enable', '--now', $unit],
    ]);
});

it('converges a desired-stopped systemd replacement before deleting its backup', function (): void {
    $process = runtime_manager_systemd_process($this->instance);
    $unit = "orbit-process-{$process->id}-queue.service";
    $path = "/etc/systemd/system/{$unit}";
    $candidate = "/etc/orbit/systemd-candidates/{$unit}";
    $backup = "/etc/orbit/systemd-candidates/.{$unit}.backup";
    $previous = "[Unit]\nX-Orbit-Process-ID={$process->id}\nDescription=Previous\n";
    $this->ssh->responses = array_fill(start_index: 0, count: 10, value: process_runtime_result());
    $this->ssh->responses[1] = process_runtime_result(stdout: $previous);

    $this->manager->converge($process);

    expect(array_map(
        static fn (RemoteCommand $command): array => $command->arguments,
        $this->ssh->commands,
    ))->toBe([
        ['sudo', 'test', '-e', $path],
        ['sudo', 'cat', '--', $path],
        ['sudo', 'install', '-d', '-m', '0755', '/etc/orbit/systemd-candidates'],
        ['sudo', 'install', '-m', '0644', '/dev/stdin', $candidate],
        ['sudo', 'systemd-analyze', 'verify', $candidate],
        ['sudo', 'cp', '--preserve=mode,ownership,timestamps', '--', $path, $backup],
        ['sudo', 'mv', '--', $candidate, $path],
        ['sudo', 'systemctl', 'daemon-reload'],
        ['sudo', 'systemctl', 'disable', '--now', $unit],
        ['sudo', 'rm', '-f', '--', $backup],
    ]);
});

it('creates and manages a labeled Docker container through fixed SSH commands', function (): void {
    $process = runtime_manager_docker_process($this->instance);
    $owner = (string) $process->id;
    $ownership = "true\nprocess\n{$owner}";
    $desiredSpec = $this->manager->dockerSpecHash($process);
    $this->ssh->responses = [
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(),
        process_runtime_result(stdout: "{$ownership}\n{$desiredSpec}\nfalse\n"),
        process_runtime_result(stdout: $ownership),
        process_runtime_result(),
        process_runtime_result(stdout: $ownership),
        process_runtime_result(),
        process_runtime_result(stdout: $ownership),
        process_runtime_result(),
        process_runtime_result(stdout: $ownership),
        process_runtime_result(stdout: "container log\n"),
        process_runtime_result(stdout: "{$ownership}\n{$desiredSpec}\nfalse\n"),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(),
    ];

    $this->manager->converge($process);
    $this->manager->start($process);
    $this->manager->stop($process);
    $this->manager->restart($process);
    $logs = $this->manager->logs($process, 20);
    $this->manager->remove($process);

    $name = "orbit-process-{$process->id}-redis";

    expect(array_map(
        static fn (RemoteCommand $command): array => $command->arguments,
        $this->ssh->commands,
    ))
        ->toBe([
            process_runtime_docker_inspect_arguments($name),
            process_runtime_docker_inspect_arguments("{$name}-rollback-running"),
            process_runtime_docker_inspect_arguments("{$name}-rollback-stopped"),
            process_runtime_docker_inspect_arguments("{$name}-candidate"),
            process_runtime_docker_create_arguments($process, $name, $desiredSpec),
            process_runtime_docker_inspect_arguments($name),
            process_runtime_docker_owner_arguments($name),
            ['sudo', 'docker', 'container', 'start', $name],
            process_runtime_docker_owner_arguments($name),
            ['sudo', 'docker', 'container', 'stop', $name],
            process_runtime_docker_owner_arguments($name),
            ['sudo', 'docker', 'container', 'restart', $name],
            process_runtime_docker_owner_arguments($name),
            ['sudo', 'docker', 'container', 'logs', '--tail', '20', $name],
            process_runtime_docker_inspect_arguments($name),
            process_runtime_docker_inspect_arguments("{$name}-rollback-running"),
            process_runtime_docker_inspect_arguments("{$name}-rollback-stopped"),
            process_runtime_docker_inspect_arguments("{$name}-candidate"),
            ['sudo', 'docker', 'container', 'rm', '--force', $name],
        ])
        ->and($logs)
        ->toBe("container log\n")
        ->and($this->ssh->commands)
        ->each(fn ($command) => $command->shellCommand()->not->toContain('sh -c'));
});

it('holds the process runtime lock while it starts a newly converged desired-running Docker process', function (): void {
    $process = runtime_manager_docker_process($this->instance);
    $process->update(['desired_state' => 'running']);
    $name = "orbit-process-{$process->id}-redis";
    $desiredSpec = $this->manager->dockerSpecHash($process);
    $lockKey = "orbit:process-runtime:{$this->instance->node_id}:{$process->id}";
    $lockWasAvailableDuringStart = null;
    $this->ssh->beforeExecute = static function (RemoteCommand $command) use (
        $lockKey,
        $name,
        &$lockWasAvailableDuringStart,
    ): void {
        if ($command->arguments !== ['sudo', 'docker', 'container', 'start', $name]) {
            return;
        }

        $contendingLock = Cache::lock($lockKey, 60);
        $lockWasAvailableDuringStart = $contendingLock->get();

        if ($lockWasAvailableDuringStart) {
            $contendingLock->release();
        }
    };
    $this->ssh->responses = [
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(),
        process_runtime_result(stdout: "true\nprocess\n{$process->id}\n{$desiredSpec}\nfalse\n"),
        process_runtime_result(),
    ];

    $this->manager->converge($process);

    $availableAfterConvergence = Cache::lock($lockKey, 60);

    try {
        expect($lockWasAvailableDuringStart)
            ->toBeFalse()
            ->and($availableAfterConvergence->get())
            ->toBeTrue()
            ->and(array_map(
                static fn (RemoteCommand $command): array => $command->arguments,
                array_slice($this->ssh->commands, -2),
            ))
            ->toBe([
                process_runtime_docker_inspect_arguments($name),
                ['sudo', 'docker', 'container', 'start', $name],
            ]);
    } finally {
        $availableAfterConvergence->release();
    }
});

it('retains a failed new Docker runtime as an exact-owned stopped canonical and starts it on retry', function (): void {
    $process = runtime_manager_docker_process($this->instance);
    $process->update(['desired_state' => 'running']);
    $name = "orbit-process-{$process->id}-redis";
    $candidate = "{$name}-candidate";
    $rollback = "{$name}-rollback-running";
    $desiredSpec = $this->manager->dockerSpecHash($process);
    $this->ssh->responses = [
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(),
        process_runtime_result(stdout: "true\nprocess\n{$process->id}\n{$desiredSpec}\nfalse\n"),
        process_runtime_result(1, stderr: 'new container start failed'),
        process_runtime_result(stdout: "true\nprocess\n{$process->id}\n{$desiredSpec}\nfalse\n"),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(),
    ];

    $failure = null;

    try {
        $this->manager->converge($process);
    } catch (ProcessOperationException $exception) {
        $failure = $exception;
    }

    expect($failure)
        ->toBeInstanceOf(ProcessOperationException::class)
        ->errorCode->toBe('process.start_failed')
        ->step->toBe('start')->and(array_map(
            static fn (RemoteCommand $command): array => $command->arguments,
            array_slice($this->ssh->commands, -2),
        ))->toBe([
            process_runtime_docker_inspect_arguments($name),
            ['sudo', 'docker', 'container', 'start', $name],
        ])->and(array_map(
            static fn (RemoteCommand $command): array => $command->arguments,
            $this->ssh->commands,
        ))
        ->not->toContain(['sudo', 'docker', 'container', 'rm', '--force', $name])
        ->not->toContain(['sudo', 'docker', 'container', 'rename', $name, $rollback])
        ->not->toContain(['sudo', 'docker', 'container', 'rename', $name, $candidate]);

    $releasedLock = Cache::lock("orbit:process-runtime:{$this->instance->node_id}:{$process->id}", 60);

    try {
        expect($releasedLock->get())->toBeTrue();
    } finally {
        $releasedLock->release();
    }

    $this->manager->converge($process);

    expect(array_map(
        static fn (RemoteCommand $command): array => $command->arguments,
        array_slice($this->ssh->commands, offset: 7),
    ))->toBe([
        process_runtime_docker_inspect_arguments($name),
        process_runtime_docker_inspect_arguments("{$name}-rollback-running"),
        process_runtime_docker_inspect_arguments("{$name}-rollback-stopped"),
        process_runtime_docker_inspect_arguments($candidate),
        ['sudo', 'docker', 'container', 'start', $name],
    ]);
});

it('removes the previous running Docker container only after the replacement starts', function (): void {
    $process = runtime_manager_docker_process($this->instance);
    $process->update(['desired_state' => 'running']);
    $name = "orbit-process-{$process->id}-redis";
    $candidate = "{$name}-candidate";
    $rollback = "{$name}-rollback-running";
    $desiredSpec = $this->manager->dockerSpecHash($process);
    $this->ssh->responses = [
        process_runtime_result(stdout: "true\nprocess\n{$process->id}\nold-spec\ntrue\n"),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(),
        process_runtime_result(stdout: "true\nprocess\n{$process->id}\n{$desiredSpec}\nfalse\n"),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
    ];

    $this->manager->converge($process);

    expect(array_map(
        static fn (RemoteCommand $command): array => $command->arguments,
        array_slice($this->ssh->commands, offset: 6),
    ))->toBe([
        ['sudo', 'docker', 'container', 'rename', $name,      $rollback],
        ['sudo', 'docker', 'container', 'stop',   $rollback],
        ['sudo', 'docker', 'container', 'rename', $candidate, $name],
        ['sudo', 'docker', 'container', 'start',  $name],
        ['sudo', 'docker', 'container', 'rm',     '--force',  $rollback],
    ]);
});

it('restores the prior Docker name and running state when replacement start fails', function (): void {
    $process = runtime_manager_docker_process($this->instance);
    $process->update(['desired_state' => 'running']);
    $name = "orbit-process-{$process->id}-redis";
    $candidate = "{$name}-candidate";
    $rollback = "{$name}-rollback-running";
    $desiredSpec = $this->manager->dockerSpecHash($process);
    $this->ssh->responses = [
        process_runtime_result(stdout: "true\nprocess\n{$process->id}\nold-spec\ntrue\n"),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(),
        process_runtime_result(stdout: "true\nprocess\n{$process->id}\n{$desiredSpec}\nfalse\n"),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(1, stderr: 'replacement start failed'),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
    ];

    try {
        $this->manager->converge($process);
    } catch (ProcessOperationException $exception) {
        expect($exception->errorCode)
            ->toBe('process.start_failed')
            ->and($exception->step)
            ->toBe('start')
            ->and(array_map(
                static fn (RemoteCommand $command): array => $command->arguments,
                array_slice($this->ssh->commands, offset: 6),
            ))
            ->toBe([
                ['sudo', 'docker', 'container', 'rename', $name, $rollback],
                ['sudo', 'docker', 'container', 'stop', $rollback],
                ['sudo', 'docker', 'container', 'rename', $candidate, $name],
                ['sudo', 'docker', 'container', 'start', $name],
                ['sudo', 'docker', 'container', 'rename', $name, $candidate],
                ['sudo', 'docker', 'container', 'stop', $candidate],
                ['sudo', 'docker', 'container', 'start', $rollback],
                ['sudo', 'docker', 'container', 'rename', $rollback, $name],
                ['sudo', 'docker', 'container', 'rm', '--force', $candidate],
            ]);

        return;
    }

    $this->fail('Expected failed Docker replacement start to restore the previous container.');
});

it('executes Docker replacement rollback and retry to the exact final artifact state', function (): void {
    $process = runtime_manager_docker_process($this->instance);
    $process->update(['desired_state' => 'running']);
    $name = "orbit-process-{$process->id}-redis";
    $desiredSpec = $this->manager->dockerSpecHash($process);
    $ssh = new ProcessRuntimeStatefulDockerSshExecutor;
    $ssh->containers[$name] = [
        'managed' => 'true',
        'kind' => 'process',
        'owner_id' => (string) $process->id,
        'spec' => 'old-spec',
        'running' => true,
    ];
    $ssh->failOnceArguments = ['sudo', 'docker', 'container', 'start', $name];
    $manager = new RemoteProcessRuntimeManager(
        targets: new ProcessTargetResolver,
        ssh: $ssh,
        keys: new ProcessRuntimeFakeSshKeyProvider,
        knownHosts: new ProcessRuntimeFakeKnownHostsStore,
        systemd: new SystemdProcessRenderer,
        docker: new DockerProcessRenderer,
    );

    expect(fn () => $manager->converge($process))
        ->toThrow(ProcessOperationException::class, 'previous container was restored');

    expect($ssh->containers)->toBe([
        $name => [
            'managed' => 'true',
            'kind' => 'process',
            'owner_id' => (string) $process->id,
            'spec' => 'old-spec',
            'running' => true,
        ],
    ]);

    $manager->converge($process);

    expect($ssh->containers)->toBe([
        $name => [
            'managed' => 'true',
            'kind' => 'process',
            'owner_id' => (string) $process->id,
            'spec' => $desiredSpec,
            'running' => true,
        ],
    ]);
});

it('restores a previously stopped Docker container without starting it when replacement start fails', function (): void {
    $process = runtime_manager_docker_process($this->instance);
    $process->update(['desired_state' => 'running']);
    $name = "orbit-process-{$process->id}-redis";
    $candidate = "{$name}-candidate";
    $rollback = "{$name}-rollback-stopped";
    $desiredSpec = $this->manager->dockerSpecHash($process);
    $this->ssh->responses = [
        process_runtime_result(stdout: "true\nprocess\n{$process->id}\nold-spec\nfalse\n"),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(),
        process_runtime_result(stdout: "true\nprocess\n{$process->id}\n{$desiredSpec}\nfalse\n"),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(1, stderr: 'replacement start failed'),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
    ];

    expect(fn () => $this->manager->converge($process))
        ->toThrow(ProcessOperationException::class, 'previous container was restored');

    expect(array_map(
        static fn (RemoteCommand $command): array => $command->arguments,
        array_slice($this->ssh->commands, offset: 6),
    ))->toBe([
        ['sudo', 'docker', 'container', 'rename', $name,      $rollback],
        ['sudo', 'docker', 'container', 'rename', $candidate, $name],
        ['sudo', 'docker', 'container', 'start',  $name],
        ['sudo', 'docker', 'container', 'rename', $name,      $candidate],
        ['sudo', 'docker', 'container', 'stop',   $candidate],
        ['sudo', 'docker', 'container', 'stop',   $rollback],
        ['sudo', 'docker', 'container', 'rename', $rollback,  $name],
        ['sudo', 'docker', 'container', 'rm',     '--force',  $candidate],
    ]);
});

it('keeps recovery artifacts after rollback state restoration fails and retries safely', function (): void {
    $sensitiveValue = 'replacement-start-secret';
    $process = runtime_manager_docker_process($this->instance, ['APP_KEY' => $sensitiveValue]);
    $process->update(['desired_state' => 'running']);
    $name = "orbit-process-{$process->id}-redis";
    $candidate = "{$name}-candidate";
    $rollback = "{$name}-rollback-running";
    $desiredSpec = $this->manager->dockerSpecHash($process);
    $this->ssh->responses = [
        process_runtime_result(stdout: "true\nprocess\n{$process->id}\nold-spec\ntrue\n"),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(),
        process_runtime_result(stdout: "true\nprocess\n{$process->id}\n{$desiredSpec}\nfalse\n"),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(1, stderr: "replacement failed: {$sensitiveValue}"),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(1, stderr: "restore start failed: {$sensitiveValue}"),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(stdout: "true\nprocess\n{$process->id}\nold-spec\nfalse\n"),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(stdout: "true\nprocess\n{$process->id}\n{$desiredSpec}\nfalse\n"),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(stdout: "true\nprocess\n{$process->id}\n{$desiredSpec}\nfalse\n"),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(stdout: "true\nprocess\n{$process->id}\n{$desiredSpec}\nfalse\n"),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
    ];

    $failure = null;

    try {
        $this->manager->converge($process);
    } catch (ProcessOperationException $exception) {
        $failure = $exception;
    }

    expect($failure)
        ->toBeInstanceOf(ProcessOperationException::class)
        ->errorCode->toBe('process.docker_recovery_required')
        ->step->toBe('restore-container-state')
        ->result->stderr->not->toContain($sensitiveValue)->and(array_map(
            static fn (RemoteCommand $command): array => $command->arguments,
            array_slice($this->ssh->commands, -3),
        ))->toBe([
            ['sudo', 'docker', 'container', 'rename', $name, $candidate],
            ['sudo', 'docker', 'container', 'stop', $candidate],
            ['sudo', 'docker', 'container', 'start', $rollback],
        ]);

    expect($this->ssh->commands)->toHaveCount(13);

    $this->manager->converge($process);

    $retryArguments = array_map(
        static fn (RemoteCommand $command): array => $command->arguments,
        array_slice($this->ssh->commands, offset: 13),
    );
    $createArguments = $retryArguments[8];
    $retryArguments[8] = ['protected-docker-create'];

    expect($createArguments)
        ->toBe(process_runtime_docker_create_arguments($process, $candidate, $desiredSpec))
        ->and($retryArguments)
        ->toBe([
            process_runtime_docker_inspect_arguments($name),
            process_runtime_docker_inspect_arguments($rollback),
            process_runtime_docker_inspect_arguments("{$name}-rollback-stopped"),
            process_runtime_docker_inspect_arguments($candidate),
            ['sudo', 'docker', 'container', 'start', $rollback],
            ['sudo', 'docker', 'container', 'rename', $rollback, $name],
            process_runtime_docker_inspect_arguments($candidate),
            ['sudo', 'docker', 'container', 'rm', '--force', $candidate],
            ['protected-docker-create'],
            process_runtime_docker_inspect_arguments($candidate),
            ['sudo', 'docker', 'container', 'rename', $name, $rollback],
            ['sudo', 'docker', 'container', 'stop', $rollback],
            ['sudo', 'docker', 'container', 'rename', $candidate, $name],
            ['sudo', 'docker', 'container', 'start', $name],
            ['sudo', 'docker', 'container', 'rm', '--force', $rollback],
        ])
        ->and(implode(
            "\0",
            array_merge(...array_map(
                static fn (RemoteCommand $command): array => $command->arguments,
                $this->ssh->commands,
            )),
        ))
        ->not
        ->toContain($sensitiveValue)
        ->and($this->ssh->responses)
        ->toBeEmpty();
});

it('stops a retained running replacement candidate before restoring rollback state on retry', function (): void {
    $process = runtime_manager_docker_process($this->instance);
    $process->update(['desired_state' => 'running']);
    $name = "orbit-process-{$process->id}-redis";
    $candidate = "{$name}-candidate";
    $rollback = "{$name}-rollback-running";
    $desiredSpec = $this->manager->dockerSpecHash($process);
    $this->ssh->responses = [
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(stdout: "true\nprocess\n{$process->id}\n{$desiredSpec}\nfalse\n"),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(stdout: "true\nprocess\n{$process->id}\n{$desiredSpec}\ntrue\n"),
        process_runtime_result(1, stderr: 'candidate stop failed'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(stdout: "true\nprocess\n{$process->id}\n{$desiredSpec}\nfalse\n"),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(stdout: "true\nprocess\n{$process->id}\n{$desiredSpec}\ntrue\n"),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(stdout: "true\nprocess\n{$process->id}\n{$desiredSpec}\nfalse\n"),
        process_runtime_result(),
    ];

    try {
        $this->manager->converge($process);
    } catch (ProcessOperationException $exception) {
        expect($exception->errorCode)
            ->toBe('process.docker_recovery_required')
            ->and($exception->step)
            ->toBe('stop-recovery-candidate');
    }

    expect($this->ssh->commands)->toHaveCount(5);

    $this->manager->converge($process);

    expect(array_map(
        static fn (RemoteCommand $command): array => $command->arguments,
        array_slice($this->ssh->commands, offset: 5),
    ))->toBe([
        process_runtime_docker_inspect_arguments($name),
        process_runtime_docker_inspect_arguments($rollback),
        process_runtime_docker_inspect_arguments("{$name}-rollback-stopped"),
        process_runtime_docker_inspect_arguments($candidate),
        ['sudo', 'docker', 'container', 'stop', $candidate],
        ['sudo', 'docker', 'container', 'start', $rollback],
        ['sudo', 'docker', 'container', 'rename', $rollback, $name],
        process_runtime_docker_inspect_arguments($candidate),
        ['sudo', 'docker', 'container', 'rm', '--force', $candidate],
    ]);
});

it('restores the previous running Docker container when rollback cleanup fails after replacement start', function (): void {
    $process = runtime_manager_docker_process($this->instance);
    $process->update(['desired_state' => 'running']);
    $name = "orbit-process-{$process->id}-redis";
    $candidate = "{$name}-candidate";
    $rollback = "{$name}-rollback-running";
    $desiredSpec = $this->manager->dockerSpecHash($process);
    $this->ssh->responses = [
        process_runtime_result(stdout: "true\nprocess\n{$process->id}\nold-spec\ntrue\n"),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(),
        process_runtime_result(stdout: "true\nprocess\n{$process->id}\n{$desiredSpec}\nfalse\n"),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(1, stderr: 'rollback cleanup failed'),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
    ];

    try {
        $this->manager->converge($process);
    } catch (ProcessOperationException $exception) {
        expect($exception->errorCode)
            ->toBe('process.docker_activation_failed')
            ->and($exception->step)
            ->toBe('finalize-container')
            ->and(array_map(
                static fn (RemoteCommand $command): array => $command->arguments,
                array_slice($this->ssh->commands, offset: 6),
            ))
            ->toBe([
                ['sudo', 'docker', 'container', 'rename', $name,      $rollback],
                ['sudo', 'docker', 'container', 'stop',   $rollback],
                ['sudo', 'docker', 'container', 'rename', $candidate, $name],
                ['sudo', 'docker', 'container', 'start',  $name],
                ['sudo', 'docker', 'container', 'rm',     '--force',  $rollback],
                ['sudo', 'docker', 'container', 'rename', $name,      $candidate],
                ['sudo', 'docker', 'container', 'stop',   $candidate],
                ['sudo', 'docker', 'container', 'start',  $rollback],
                ['sudo', 'docker', 'container', 'rename', $rollback,  $name],
                ['sudo', 'docker', 'container', 'rm',     '--force',  $candidate],
            ]);

        return;
    }

    $this->fail('Expected failed rollback cleanup to restore the previous running container.');
});

it('streams Docker environment secrets through a fixed protected environment-file command', function (): void {
    $sensitiveValue = 'opaque-value-with-spaces-and-symbols-!@#';
    $process = runtime_manager_docker_process($this->instance, [
        'ZEBRA' => 'last',
        'DATABASE_URL' => $sensitiveValue,
        'ALPHA' => 'first',
    ]);
    $desiredSpec = $this->manager->dockerSpecHash($process);
    $this->ssh->responses = [
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(),
        process_runtime_result(stdout: "true\nprocess\n{$process->id}\n{$desiredSpec}\nfalse\n"),
    ];

    $this->manager->converge($process);

    $create = $this->ssh->commands[4];
    $debugOutput = print_r($create, return: true);

    expect(array_slice(array: $create->arguments, offset: 0, length: 3))
        ->toBe(['bash', '-seu', '-c'])
        ->and($create->arguments[3])
        ->toContain('umask 077')
        ->toContain('mktemp')
        ->toContain('trap \'rm -f -- "$environment_file"\' EXIT')
        ->toContain('cat > "$environment_file"')
        ->toContain('chmod 0600 "$environment_file"')
        ->toContain('sudo docker container create --env-file "$environment_file" "$@"')
        ->and($create->input)
        ->toBeNull()
        ->and($create->protectedInput)
        ->toBeInstanceOf(ProtectedInput::class)
        ->and($this->ssh->protectedInputHashes)
        ->toBe([hash('sha256', "ALPHA=first\nDATABASE_URL={$sensitiveValue}\nZEBRA=last\n")])
        ->and(implode("\0", $create->arguments))
        ->not->toContain($sensitiveValue)->and($create->shellCommand())
        ->not->toContain($sensitiveValue)->and($debugOutput)
        ->not->toContain($sensitiveValue)->toContain('[PROTECTED]');

    expect(fn () => $create->protectedInput?->stream())
        ->toThrow(LogicException::class, 'closed');
});

it('executes the protected Docker environment-file boundary and removes the temporary file', function (
    int $dockerExitCode,
): void {
    $sensitiveValue = 'sentinel-secret-never-in-argv';
    $environmentPayload = "ALPHA=first\nDATABASE_URL={$sensitiveValue}\n";
    $directory = sys_get_temp_dir().'/orbit-docker-environment-'.bin2hex(random_bytes(8));
    $capture = "{$directory}/capture";
    $fakeSudo = "{$directory}/sudo";
    $filesystem = new Filesystem;
    $filesystem->makeDirectory($directory, 0o700);
    $filesystem->put($fakeSudo, implode("\n", [
        '#!/usr/bin/env bash',
        'set -euo pipefail',
        'capture='.escapeshellarg($capture),
        '[[ "$1" == docker && "$2" == container && "$3" == create && "$4" == --env-file ]]',
        'environment_file="$5"',
        'stat -c %a "$environment_file" > "${capture}.mode"',
        'sha256sum "$environment_file" | cut -d\  -f1 > "${capture}.hash"',
        'printf %s "$environment_file" > "${capture}.path"',
        'printf "%s\\0" "$@" > "${capture}.argv"',
        "exit {$dockerExitCode}",
        '',
    ]));
    chmod(filename: $fakeSudo, permissions: 0o700);

    try {
        $ssh = new ProcessRuntimeExecutingSshExecutor(new NativeProcessRunner, $directory);
        $manager = new RemoteProcessRuntimeManager(
            targets: new ProcessTargetResolver,
            ssh: $ssh,
            keys: new ProcessRuntimeFakeSshKeyProvider,
            knownHosts: new ProcessRuntimeFakeKnownHostsStore,
            systemd: new SystemdProcessRenderer,
            docker: new DockerProcessRenderer,
        );
        $process = runtime_manager_docker_process($this->instance, [
            'DATABASE_URL' => $sensitiveValue,
            'ALPHA' => 'first',
        ]);

        $failure = null;

        try {
            $manager->converge($process);
        } catch (ProcessOperationException $exception) {
            $failure = $exception;
        }

        $environmentPath = trim($filesystem->get("{$capture}.path"));
        $dockerArguments = explode(
            separator: "\0",
            string: rtrim(string: $filesystem->get("{$capture}.argv"), characters: "\0"),
        );
        $remoteArguments = implode("\0", $ssh->commands[4]->arguments);

        expect(trim($filesystem->get("{$capture}.mode")))
            ->toBe('600')
            ->and(trim($filesystem->get("{$capture}.hash")))
            ->toBe(hash('sha256', $environmentPayload))
            ->and(array_slice(array: $dockerArguments, offset: 0, length: 5))
            ->toBe(['docker', 'container', 'create', '--env-file', $environmentPath])
            ->and($dockerArguments)
            ->toContain('--name', "orbit-process-{$process->id}-redis")
            ->and($filesystem->exists($environmentPath))
            ->toBeFalse()
            ->and($remoteArguments)
            ->not->toContain($sensitiveValue)->and($filesystem->get("{$capture}.argv"))
            ->not->toContain($sensitiveValue);

        if ($dockerExitCode === 0) {
            expect($failure)->toBeNull();

            return;
        }

        expect($failure)
            ->toBeInstanceOf(ProcessOperationException::class)
            ->and($failure?->errorCode)
            ->toBe('process.docker_converge_failed')
            ->and($failure?->step)
            ->toBe('create-container');
    } finally {
        $filesystem->deleteDirectory($directory);
    }
})->with([
    'successful Docker create' => [0],
    'failed Docker create' => [23],
]);

it('keeps the previous owned Docker container when replacement creation fails', function (): void {
    $sensitiveValue = 'replacement-secret';
    $process = runtime_manager_docker_process($this->instance, ['APP_KEY' => $sensitiveValue]);
    $name = "orbit-process-{$process->id}-redis";
    $this->ssh->responses = [
        process_runtime_result(stdout: "true\nprocess\n{$process->id}\nold-spec\nfalse\n"),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(
            1,
            stdout: "echoed {$sensitiveValue}",
            stderr: "create failed: {$sensitiveValue}",
        ),
    ];

    try {
        $this->manager->converge($process);
    } catch (ProcessOperationException $exception) {
        $commands = array_map(
            static fn (RemoteCommand $command): array => $command->arguments,
            $this->ssh->commands,
        );
        $debugOutput = print_r($exception->result, return: true);
        $exceptionText = (string) $exception;
        $traceOutput = json_encode($exception->getTrace(), JSON_THROW_ON_ERROR);
        $createArguments = $commands[4];

        expect($exception->errorCode)
            ->toBe('process.docker_converge_failed')
            ->and($exception->step)
            ->toBe('create-container')
            ->and($exception->result?->stderr)
            ->not->toContain($sensitiveValue)->and($exception->result?->stdout)
            ->not->toContain($sensitiveValue)->and($debugOutput)
            ->not->toContain($sensitiveValue)->and($exceptionText)
            ->not->toContain($sensitiveValue)->and($traceOutput)
            ->not->toContain($sensitiveValue)->and($commands)
            ->not->toContain(['sudo', 'docker', 'container', 'rm', '--force', $name])->and($commands)
            ->not->toContain(['sudo', 'docker', 'container', 'rename', $name, "{$name}-rollback-running"])
            ->not->toContain(['sudo', 'docker', 'container', 'rename', $name, "{$name}-rollback-stopped"]);

        expect($createArguments)
            ->toContain('--name', "{$name}-candidate")
            ->and(implode("\0", $createArguments))
            ->not->toContain($sensitiveValue);

        return;
    }

    $this->fail('Expected replacement creation to fail without mutating the previous container.');
});

it('validates replacement rendering before mutating the previous Docker container', function (): void {
    $process = runtime_manager_docker_process($this->instance);
    $runtimeConfig = $process->runtime_config;
    $runtimeConfig['image'] = '--privileged';
    $process->forceFill(['runtime_config' => $runtimeConfig])->save();
    $name = "orbit-process-{$process->id}-redis";
    $this->ssh->responses = [
        process_runtime_result(stdout: "true\nprocess\n{$process->id}\nold-spec\nfalse\n"),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
    ];

    expect(fn () => $this->manager->converge($process))
        ->toThrow(InvalidArgumentException::class, 'image');

    expect(array_map(
        static fn (RemoteCommand $command): array => $command->arguments,
        $this->ssh->commands,
    ))->toBe([
        process_runtime_docker_inspect_arguments($name),
        process_runtime_docker_inspect_arguments("{$name}-rollback-running"),
        process_runtime_docker_inspect_arguments("{$name}-rollback-stopped"),
        process_runtime_docker_inspect_arguments("{$name}-candidate"),
    ]);
});

it('restores the previous owned Docker container when candidate activation fails', function (): void {
    $process = runtime_manager_docker_process($this->instance);
    $name = "orbit-process-{$process->id}-redis";
    $candidate = "{$name}-candidate";
    $rollback = "{$name}-rollback-stopped";
    $desiredSpec = $this->manager->dockerSpecHash($process);
    $this->ssh->responses = [
        process_runtime_result(stdout: "true\nprocess\n{$process->id}\nold-spec\nfalse\n"),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(),
        process_runtime_result(stdout: "true\nprocess\n{$process->id}\n{$desiredSpec}\nfalse\n"),
        process_runtime_result(),
        process_runtime_result(1, stderr: 'rename candidate failed'),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(),
    ];

    try {
        $this->manager->converge($process);
    } catch (ProcessOperationException $exception) {
        expect($exception->errorCode)
            ->toBe('process.docker_activation_failed')
            ->and($exception->step)
            ->toBe('activate-container')
            ->and(array_map(
                static fn (RemoteCommand $command): array => $command->arguments,
                $this->ssh->commands,
            ))
            ->toBe([
                process_runtime_docker_inspect_arguments($name),
                process_runtime_docker_inspect_arguments("{$name}-rollback-running"),
                process_runtime_docker_inspect_arguments($rollback),
                process_runtime_docker_inspect_arguments($candidate),
                process_runtime_docker_create_arguments($process, $candidate, $desiredSpec),
                process_runtime_docker_inspect_arguments($candidate),
                ['sudo', 'docker', 'container', 'rename', $name, $rollback],
                ['sudo', 'docker', 'container', 'rename', $candidate, $name],
                ['sudo', 'docker', 'container', 'stop', $rollback],
                ['sudo', 'docker', 'container', 'rename', $rollback, $name],
                ['sudo', 'docker', 'container', 'rm', '--force', $candidate],
            ]);

        return;
    }

    $this->fail('Expected Docker activation to restore the previous container.');
});

it('returns a recovery-required Docker error when the previous container cannot be restored', function (): void {
    $process = runtime_manager_docker_process($this->instance);
    $name = "orbit-process-{$process->id}-redis";
    $candidate = "{$name}-candidate";
    $rollback = "{$name}-rollback-stopped";
    $desiredSpec = $this->manager->dockerSpecHash($process);
    $this->ssh->responses = [
        process_runtime_result(stdout: "true\nprocess\n{$process->id}\nold-spec\nfalse\n"),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(),
        process_runtime_result(stdout: "true\nprocess\n{$process->id}\n{$desiredSpec}\nfalse\n"),
        process_runtime_result(),
        process_runtime_result(1, stderr: 'rename candidate failed'),
        process_runtime_result(),
        process_runtime_result(1, stderr: 'restore failed'),
    ];

    try {
        $this->manager->converge($process);
    } catch (ProcessOperationException $exception) {
        expect($exception->errorCode)
            ->toBe('process.docker_recovery_required')
            ->and($exception->step)
            ->toBe('restore-container')
            ->and(array_map(
                static fn (RemoteCommand $command): array => $command->arguments,
                array_slice($this->ssh->commands, -4),
            ))
            ->toBe([
                ['sudo', 'docker', 'container', 'rename', $name,      $rollback],
                ['sudo', 'docker', 'container', 'rename', $candidate, $name],
                ['sudo', 'docker', 'container', 'stop',   $rollback],
                ['sudo', 'docker', 'container', 'rename', $rollback,  $name],
            ]);

        return;
    }

    $this->fail('Expected a distinct Docker rollback error.');
});

it('recovers an exact-owned Docker rollback artifact when the canonical name is absent', function (): void {
    $process = runtime_manager_docker_process($this->instance);
    $name = "orbit-process-{$process->id}-redis";
    $rollback = "{$name}-rollback-stopped";
    $desiredSpec = $this->manager->dockerSpecHash($process);
    $this->ssh->responses = [
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(stdout: "true\nprocess\n{$process->id}\n{$desiredSpec}\nfalse\n"),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(),
        process_runtime_result(),
        process_runtime_result(1, stderr: 'Error: No such object'),
    ];

    $this->manager->converge($process);

    expect(array_map(
        static fn (RemoteCommand $command): array => $command->arguments,
        $this->ssh->commands,
    ))->toBe([
        process_runtime_docker_inspect_arguments($name),
        process_runtime_docker_inspect_arguments("{$name}-rollback-running"),
        process_runtime_docker_inspect_arguments($rollback),
        process_runtime_docker_inspect_arguments("{$name}-candidate"),
        ['sudo', 'docker', 'container', 'stop', $rollback],
        ['sudo', 'docker', 'container', 'rename', $rollback, $name],
        process_runtime_docker_inspect_arguments("{$name}-candidate"),
    ]);
});

it('fails closed without mutation when both Docker rollback state markers exist', function (): void {
    $process = runtime_manager_docker_process($this->instance);
    $name = "orbit-process-{$process->id}-redis";
    $owned = "true\nprocess\n{$process->id}\nspec\nfalse\n";
    $this->ssh->responses = [
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(stdout: $owned),
        process_runtime_result(stdout: $owned),
        process_runtime_result(1, stderr: 'Error: No such object'),
    ];

    try {
        $this->manager->converge($process);
    } catch (ProcessOperationException $exception) {
        expect($exception->errorCode)
            ->toBe('process.docker_recovery_required')
            ->and($exception->step)
            ->toBe('inspect-rollback-container')
            ->and($this->ssh->commands)
            ->toHaveCount(4)
            ->and($this->ssh->responses)
            ->toBeEmpty();

        return;
    }

    $this->fail('Expected ambiguous Docker rollback markers to fail closed.');
});

it('refuses a colliding Docker container without the matching Orbit owner label', function (): void {
    $process = runtime_manager_docker_process($this->instance);
    $this->ssh->responses = [
        process_runtime_result(stdout: "true\nprocess\n999\nsome-hash\n"),
    ];

    expect(fn () => $this->manager->converge($process))
        ->toThrow(ProcessOperationException::class, 'not owned by this process');

    expect($this->ssh->commands)->toHaveCount(1);
});

it('requires every Docker ownership label before accepting a canonical container', function (): void {
    $process = runtime_manager_docker_process($this->instance);
    $desiredSpec = $this->manager->dockerSpecHash($process);
    $this->ssh->responses = [
        process_runtime_result(stdout: "{$process->id}\n{$desiredSpec}\n"),
    ];

    try {
        $this->manager->converge($process);
    } catch (ProcessOperationException $exception) {
        expect($exception->errorCode)
            ->toBe('process.runtime_name_collision')
            ->and($exception->step)
            ->toBe('inspect-container')
            ->and($this->ssh->commands)
            ->toHaveCount(1);

        return;
    }

    $this->fail('Expected incomplete Docker ownership labels to fail closed.');
});

it('requires every Docker ownership label before lifecycle mutation', function (): void {
    $process = runtime_manager_docker_process($this->instance);
    $this->ssh->responses = [process_runtime_result(stdout: (string) $process->id)];

    expect(fn () => $this->manager->start($process))
        ->toThrow(ProcessOperationException::class, 'not owned by this process');

    expect($this->ssh->commands)->toHaveCount(1);
});

it('removes every exact-owned Docker recovery artifact before the process record can be deleted', function (): void {
    $process = runtime_manager_docker_process($this->instance);
    $name = "orbit-process-{$process->id}-redis";
    $candidate = "{$name}-candidate";
    $runningRollback = "{$name}-rollback-running";
    $stoppedRollback = "{$name}-rollback-stopped";
    $owned = "true\nprocess\n{$process->id}\nspec\nfalse\n";
    $this->ssh->responses = [
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(stdout: $owned),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(stdout: $owned),
        process_runtime_result(),
        process_runtime_result(),
    ];

    $this->manager->remove($process);

    expect(array_map(
        static fn (RemoteCommand $command): array => $command->arguments,
        $this->ssh->commands,
    ))->toBe([
        process_runtime_docker_inspect_arguments($name),
        process_runtime_docker_inspect_arguments($runningRollback),
        process_runtime_docker_inspect_arguments($stoppedRollback),
        process_runtime_docker_inspect_arguments($candidate),
        ['sudo', 'docker', 'container', 'rm', '--force', $candidate],
        ['sudo', 'docker', 'container', 'rm', '--force', $runningRollback],
    ]);
});

it('does not remove any Docker artifact when a recovery name is not exactly owned', function (): void {
    $process = runtime_manager_docker_process($this->instance);
    $name = "orbit-process-{$process->id}-redis";
    $this->ssh->responses = [
        process_runtime_result(stdout: "true\nprocess\n{$process->id}\nspec\nfalse\n"),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(1, stderr: 'Error: No such object'),
        process_runtime_result(stdout: "true\nprocess\n999\nspec\nfalse\n"),
    ];

    expect(fn () => $this->manager->remove($process))
        ->toThrow(ProcessOperationException::class, 'not owned by this process');

    expect(array_map(
        static fn (RemoteCommand $command): array => $command->arguments,
        $this->ssh->commands,
    ))->toBe([
        process_runtime_docker_inspect_arguments($name),
        process_runtime_docker_inspect_arguments("{$name}-rollback-running"),
        process_runtime_docker_inspect_arguments("{$name}-rollback-stopped"),
        process_runtime_docker_inspect_arguments("{$name}-candidate"),
    ]);
});

it('serializes runtime convergence for the same node and process', function (): void {
    $process = runtime_manager_docker_process($this->instance);
    $lock = Cache::lock(
        "orbit:process-runtime:{$this->instance->node_id}:{$process->id}",
        60,
    );

    expect($lock->get())->toBeTrue();

    try {
        try {
            $this->manager->converge($process);
        } catch (ProcessOperationException $exception) {
            expect($exception->errorCode)
                ->toBe('process.runtime_lock_failed')
                ->and($exception->step)
                ->toBe('lock-runtime')
                ->and($this->ssh->commands)
                ->toBeEmpty();

            return;
        }

        $this->fail('Expected concurrent runtime convergence to fail closed.');
    } finally {
        $lock->release();
    }
});

it('serializes lifecycle mutations with runtime convergence', function (string $operation): void {
    $process = runtime_manager_docker_process($this->instance);
    $lock = Cache::lock(
        "orbit:process-runtime:{$this->instance->node_id}:{$process->id}",
        60,
    );

    expect($lock->get())->toBeTrue();

    try {
        try {
            match ($operation) {
                'start' => $this->manager->start($process),
                'stop' => $this->manager->stop($process),
                'restart' => $this->manager->restart($process),
                'remove' => $this->manager->remove($process),
            };
        } catch (ProcessOperationException $exception) {
            expect($exception->errorCode)
                ->toBe('process.runtime_lock_failed')
                ->and($exception->step)
                ->toBe('lock-runtime')
                ->and($this->ssh->commands)
                ->toBeEmpty();

            return;
        }

        $this->fail("Expected concurrent runtime {$operation} to fail closed.");
    } finally {
        $lock->release();
    }
})->with(['start', 'stop', 'restart', 'remove']);

it('rechecks exact systemd ownership before lifecycle operations', function (string $operation): void {
    $process = runtime_manager_systemd_process($this->instance);
    $this->ssh->responses = [
        process_runtime_result(),
        process_runtime_result(stdout: "[Unit]\nX-Orbit-Process-ID={$process->id}0\n"),
    ];

    expect(fn () => match ($operation) {
        'start' => $this->manager->start($process),
        'stop' => $this->manager->stop($process),
        'restart' => $this->manager->restart($process),
    })
        ->toThrow(ProcessOperationException::class, 'not owned by this process');

    expect($this->ssh->commands)->toHaveCount(2);
})->with(['start', 'stop', 'restart']);

it('rechecks exact ownership before reading systemd logs', function (): void {
    $process = runtime_manager_systemd_process($this->instance);
    $this->ssh->responses = [
        process_runtime_result(),
        process_runtime_result(stdout: "[Unit]\nDescription=Personal service\n"),
    ];

    expect(fn () => $this->manager->logs($process, 20))
        ->toThrow(ProcessOperationException::class, 'not owned by this process');

    expect($this->ssh->commands)->toHaveCount(2);
});

it('requires a successful systemd stop before deleting an owned unit', function (): void {
    $process = runtime_manager_systemd_process($this->instance);
    $this->ssh->responses = [
        process_runtime_result(),
        process_runtime_result(stdout: "[Unit]\nX-Orbit-Process-ID={$process->id}\n"),
        process_runtime_result(1, stderr: 'Failed to disable unit'),
    ];

    try {
        $this->manager->remove($process);
    } catch (ProcessOperationException $exception) {
        expect($exception->errorCode)
            ->toBe('process.remove_failed')
            ->and($exception->step)
            ->toBe('stop');

        expect(array_map(
            static fn (RemoteCommand $command): array => $command->arguments,
            $this->ssh->commands,
        ))->toBe([
            ['sudo', 'test', '-e', "/etc/systemd/system/orbit-process-{$process->id}-queue.service"],
            ['sudo', 'cat', '--', "/etc/systemd/system/orbit-process-{$process->id}-queue.service"],
            ['sudo', 'systemctl', 'disable', '--now', "orbit-process-{$process->id}-queue.service"],
        ]);

        return;
    }

    $this->fail('Expected removal to stop after disable failed.');
});

it('rechecks exact Docker ownership before lifecycle control', function (): void {
    $process = runtime_manager_docker_process($this->instance);
    $this->ssh->responses = [process_runtime_result(stdout: '999')];

    expect(fn () => $this->manager->start($process))
        ->toThrow(ProcessOperationException::class, 'not owned by this process');

    expect($this->ssh->commands)->toHaveCount(1);
});

it('returns absent only for a native systemd not-found status outcome', function (): void {
    $process = runtime_manager_systemd_process($this->instance);
    $this->ssh->responses = [process_runtime_result(1)];

    expect($this->manager->status($process))->toBe('absent');
});

it('does not treat a successful systemd ownership probe warning as absence', function (): void {
    $process = runtime_manager_systemd_process($this->instance);
    $this->ssh->responses = [
        process_runtime_result(),
        process_runtime_result(
            stdout: "[Unit]\nX-Orbit-Process-ID={$process->id}\n",
            stderr: 'warning: optional metadata not found',
        ),
        process_runtime_result(stdout: 'active'),
    ];

    expect($this->manager->status($process))
        ->toBe('active')
        ->and($this->ssh->commands[2]->arguments)
        ->toBe(['sudo', 'systemctl', 'is-active', "orbit-process-{$process->id}-queue.service"]);
});

it('returns a stable status error for a failed systemd probe', function (): void {
    $process = runtime_manager_systemd_process($this->instance);
    $this->ssh->responses = [process_runtime_result(1, stderr: 'sudo: permission denied')];

    try {
        $this->manager->status($process);
    } catch (ProcessOperationException $exception) {
        expect($exception->errorCode)
            ->toBe('process.status_failed')
            ->and($exception->step)
            ->toBe('status');

        return;
    }

    $this->fail('Expected a failed status probe to return a stable error.');
});

it('does not accept arbitrary output from a failed systemd status command', function (): void {
    $process = runtime_manager_systemd_process($this->instance);
    $this->ssh->responses = [
        process_runtime_result(),
        process_runtime_result(stdout: "[Unit]\nX-Orbit-Process-ID={$process->id}\n"),
        process_runtime_result(1, stdout: 'transport failure'),
    ];

    try {
        $this->manager->status($process);
    } catch (ProcessOperationException $exception) {
        expect($exception->errorCode)
            ->toBe('process.status_failed')
            ->and($exception->step)
            ->toBe('status');

        return;
    }

    $this->fail('Expected arbitrary failed status output to return a stable error.');
});

it('returns absent only for a native Docker not-found status outcome', function (): void {
    $process = runtime_manager_docker_process($this->instance);
    $this->ssh->responses = [process_runtime_result(1, stderr: 'Error: No such object')];

    expect($this->manager->status($process))->toBe('absent');
});

it('does not treat a successful Docker ownership probe warning as absence', function (): void {
    $process = runtime_manager_docker_process($this->instance);
    $this->ssh->responses = [
        process_runtime_result(
            stdout: "true\nprocess\n{$process->id}",
            stderr: 'warning: No such object exists in another namespace',
        ),
        process_runtime_result(stdout: 'running'),
    ];

    expect($this->manager->status($process))->toBe('running');
});

it('returns a stable status error for a failed Docker probe', function (): void {
    $process = runtime_manager_docker_process($this->instance);
    $this->ssh->responses = [process_runtime_result(1, stderr: 'Cannot connect to the Docker daemon')];

    try {
        $this->manager->status($process);
    } catch (ProcessOperationException $exception) {
        expect($exception->errorCode)
            ->toBe('process.status_failed')
            ->and($exception->step)
            ->toBe('status');

        return;
    }

    $this->fail('Expected a failed status probe to return a stable error.');
});

function runtime_manager_systemd_process(Instance $instance): Process
{
    return Process::query()->create([
        'owner_type' => Instance::class,
        'owner_id' => $instance->id,
        'name' => 'queue',
        'runtime' => ProcessRuntime::Systemd,
        'working_directory' => $instance->checkout_path,
        'runtime_config' => [
            'command' => ['/usr/bin/php', 'artisan', 'queue:work'],
            'environment_file' => $instance->checkout_path.'/.env',
        ],
        'restart_policy' => 'always',
        'desired_state' => 'stopped',
        'status' => LifecycleStatus::Active,
    ]);
}

/** @param array<string, string> $environment */
function runtime_manager_docker_process(Instance $instance, array $environment = []): Process
{
    return Process::query()->create([
        'owner_type' => Instance::class,
        'owner_id' => $instance->id,
        'name' => 'redis',
        'runtime' => ProcessRuntime::Docker,
        'working_directory' => '/data',
        'runtime_config' => [
            'image' => 'redis:8-alpine',
            'command' => ['redis-server'],
            'environment' => $environment,
            'ports' => ['127.0.0.1:6380:6379/tcp'],
            'volumes' => [['source' => 'redis-data', 'target' => '/data', 'read_only' => false]],
        ],
        'restart_policy' => 'unless-stopped',
        'desired_state' => 'stopped',
        'status' => LifecycleStatus::Active,
    ]);
}

function process_runtime_result(
    int $exitCode = 0,
    string $stdout = '',
    string $stderr = '',
): CommandResult {
    return new CommandResult($exitCode, $stdout, $stderr, 1, false);
}

/** @return non-empty-list<string> */
function process_runtime_docker_inspect_arguments(string $name): array
{
    return [
        'sudo',
        'docker',
        'container',
        'inspect',
        '--format',
        '{{ index .Config.Labels "orbit.managed" }}{{ printf "\\n" }}{{ index .Config.Labels "orbit.container.kind" }}{{ printf "\\n" }}{{ index .Config.Labels "orbit.process.id" }}{{ printf "\\n" }}{{ index .Config.Labels "orbit.process.spec" }}{{ printf "\\n" }}{{ .State.Running }}',
        $name,
    ];
}

/** @return non-empty-list<string> */
function process_runtime_docker_owner_arguments(string $name): array
{
    return [
        'sudo',
        'docker',
        'container',
        'inspect',
        '--format',
        '{{ index .Config.Labels "orbit.managed" }}{{ printf "\\n" }}{{ index .Config.Labels "orbit.container.kind" }}{{ printf "\\n" }}{{ index .Config.Labels "orbit.process.id" }}',
        $name,
    ];
}

/** @return non-empty-list<string> */
function process_runtime_docker_create_arguments(Process $process, string $name, string $spec): array
{
    $script = <<<'BASH'
        umask 077
        environment_file=$(mktemp /tmp/orbit-process-environment.XXXXXX)
        trap 'rm -f -- "$environment_file"' EXIT
        cat > "$environment_file"
        chmod 0600 "$environment_file"
        sudo docker container create --env-file "$environment_file" "$@"
        BASH;

    return [
        'bash',
        '-seu',
        '-c',
        $script,
        'orbit-process-docker-create',
        '--name',
        $name,
        '--label',
        'orbit.managed=true',
        '--label',
        'orbit.container.kind=process',
        '--label',
        "orbit.process.id={$process->id}",
        '--label',
        "orbit.process.spec={$spec}",
        '--restart',
        'unless-stopped',
        '--workdir',
        '/data',
        '--publish',
        '127.0.0.1:6380:6379/tcp',
        '--mount',
        'type=volume,source=redis-data,target=/data',
        'redis:8-alpine',
        'redis-server',
    ];
}

final class ProcessRuntimeFakeSshExecutor implements SshExecutor
{
    /** @var list<CommandResult> */
    public array $responses = [];

    /** @var list<SshConnection> */
    public array $connections = [];

    /** @var list<RemoteCommand> */
    public array $commands = [];

    /** @var list<string> */
    public array $protectedInputHashes = [];

    public ?Closure $beforeExecute = null;

    public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
    {
        $this->connections[] = $connection;
        $this->commands[] = $command;

        if ($this->beforeExecute instanceof Closure) {
            ($this->beforeExecute)($command);
        }

        if ($command->protectedInput instanceof ProtectedInput) {
            $contents = stream_get_contents($command->protectedInput->stream());

            if ($contents === false) {
                throw new RuntimeException('Unable to read protected test input.');
            }

            $this->protectedInputHashes[] = hash('sha256', $contents);
        }

        return array_shift($this->responses) ?? process_runtime_result();
    }
}

/** @mago-expect lint:single-class-per-file Test-local fake executes the remote boundary without opening SSH. */
final class ProcessRuntimeExecutingSshExecutor implements SshExecutor
{
    /** @var list<RemoteCommand> */
    public array $commands = [];

    private ?string $createdContainerState = null;

    public function __construct(
        private readonly ProcessRunner $runner,
        private readonly string $executableDirectory,
    ) {}

    public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
    {
        $this->commands[] = $command;

        if ($command->arguments[0] !== 'bash') {
            if ($this->createdContainerState !== null) {
                return process_runtime_result(stdout: $this->createdContainerState);
            }

            return process_runtime_result(1, stderr: 'Error: No such object');
        }

        $result = $this->runner->run(new ProcessInvocation(
            arguments: [
                '/usr/bin/env',
                '-i',
                "PATH={$this->executableDirectory}:/usr/bin:/bin",
                ...$command->arguments,
            ],
            protectedInput: $command->protectedInput,
        ));

        if (! $result->succeeded()) {
            return $result;
        }

        $labels = [];

        foreach ($command->arguments as $index => $argument) {
            if ($argument !== '--label') {
                continue;
            }

            $label = $command->arguments[$index + 1] ?? '';
            [$key, $value] = array_pad(explode('=', $label, limit: 2), length: 2, value: '');
            $labels[$key] = $value;
        }

        $this->createdContainerState = implode("\n", [
            $labels['orbit.managed'] ?? '',
            $labels['orbit.container.kind'] ?? '',
            $labels['orbit.process.id'] ?? '',
            $labels['orbit.process.spec'] ?? '',
            'false',
        ]);

        return $result;
    }
}

/**
 * @mago-expect lint:single-class-per-file Test-local fake executes Docker state transitions in memory.
 * @mago-expect lint:cyclomatic-complexity The fake implements the fixed Docker command state machine under test.
 */
final class ProcessRuntimeStatefulDockerSshExecutor implements SshExecutor
{
    /** @var array<string, array{managed: string, kind: string, owner_id: string, spec: string, running: bool}> */
    public array $containers = [];

    /** @var list<RemoteCommand> */
    public array $commands = [];

    /** @var non-empty-list<string>|null */
    public ?array $failOnceArguments = null;

    public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
    {
        $this->commands[] = $command;
        $arguments = $command->arguments;

        if ($this->failOnceArguments === $arguments) {
            $this->failOnceArguments = null;

            return process_runtime_result(1, stderr: 'configured stateful Docker failure');
        }

        if ($arguments[0] === 'bash') {
            return $this->create($arguments);
        }

        $operation = $arguments[3] ?? '';

        return match ($operation) {
            'inspect' => $this->inspect($arguments),
            'rename' => $this->rename($arguments[4], $arguments[5]),
            'start' => $this->setRunning($arguments[4], true),
            'stop' => $this->setRunning($arguments[4], false),
            'rm' => $this->remove($arguments[array_key_last($arguments)]),
            default => process_runtime_result(1, stderr: 'Unsupported stateful Docker command.'),
        };
    }

    /** @param non-empty-list<string> $arguments */
    private function create(array $arguments): CommandResult
    {
        $name = $this->valueAfter($arguments, '--name');
        $labels = [];

        foreach ($arguments as $index => $argument) {
            if ($argument !== '--label') {
                continue;
            }

            [$key, $value] = array_pad(
                explode('=', $arguments[$index + 1] ?? '', limit: 2),
                length: 2,
                value: '',
            );
            $labels[$key] = $value;
        }

        if ($name === '' || array_key_exists($name, $this->containers)) {
            return process_runtime_result(1, stderr: 'Container name collision.');
        }

        $this->containers[$name] = [
            'managed' => $labels['orbit.managed'] ?? '',
            'kind' => $labels['orbit.container.kind'] ?? '',
            'owner_id' => $labels['orbit.process.id'] ?? '',
            'spec' => $labels['orbit.process.spec'] ?? '',
            'running' => false,
        ];

        return process_runtime_result();
    }

    /** @param non-empty-list<string> $arguments */
    private function inspect(array $arguments): CommandResult
    {
        $name = $arguments[array_key_last($arguments)];
        $container = $this->containers[$name] ?? null;

        if ($container === null) {
            return process_runtime_result(1, stderr: 'Error: No such object');
        }

        return process_runtime_result(stdout: implode("\n", [
            $container['managed'],
            $container['kind'],
            $container['owner_id'],
            $container['spec'],
            $container['running'] ? 'true' : 'false',
        ]));
    }

    private function rename(string $from, string $to): CommandResult
    {
        if (! array_key_exists($from, $this->containers) || array_key_exists($to, $this->containers)) {
            return process_runtime_result(1, stderr: 'Container rename failed.');
        }

        $this->containers[$to] = $this->containers[$from];
        unset($this->containers[$from]);

        return process_runtime_result();
    }

    private function setRunning(string $name, bool $running): CommandResult
    {
        if (! array_key_exists($name, $this->containers)) {
            return process_runtime_result(1, stderr: 'Error: No such container');
        }

        $this->containers[$name]['running'] = $running;

        return process_runtime_result();
    }

    private function remove(string $name): CommandResult
    {
        if (! array_key_exists($name, $this->containers)) {
            return process_runtime_result(1, stderr: 'Error: No such container');
        }

        unset($this->containers[$name]);

        return process_runtime_result();
    }

    /** @param non-empty-list<string> $arguments */
    private function valueAfter(array $arguments, string $option): string
    {
        $index = array_search($option, $arguments, strict: true);

        if (! is_int($index)) {
            return '';
        }

        return $arguments[$index + 1] ?? '';
    }
}

/** @mago-expect lint:single-class-per-file Test-local fake keeps remote command assertions visible. */
final class ProcessRuntimeFakeSshKeyProvider implements SshKeyProvider
{
    public function ensureKeyPair(): void {}

    public function privateKeyPath(): string
    {
        return '/orbit/ssh/id_ed25519';
    }

    public function publicKey(): string
    {
        return 'ssh-ed25519 test';
    }
}

/** @mago-expect lint:single-class-per-file Test-local fake keeps remote command assertions visible. */
final class ProcessRuntimeFakeKnownHostsStore implements KnownHostsStore
{
    public function path(): string
    {
        return '/orbit/ssh/known_hosts';
    }

    public function put(string $host, int $port, \App\Infrastructure\Ssh\HostKey $key): void {}
}
