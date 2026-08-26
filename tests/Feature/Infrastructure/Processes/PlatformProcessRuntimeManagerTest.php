<?php

declare(strict_types=1);

use App\Domain\Nodes\RoleName;
use App\Domain\Processes\ProcessOperationException;
use App\Domain\Processes\ProcessRuntime;
use App\Domain\Processes\ProcessRuntimeManager;
use App\Domain\Processes\ProcessTargetResolver;
use App\Domain\Shared\LifecycleStatus;
use App\Infrastructure\Processes\PlatformProcessRuntimeManager;
use App\Models\App as OrbitApp;
use App\Models\Instance;
use App\Models\Node;
use App\Models\Process;

it('delegates Darwin launchd to the macOS manager', function (): void {
    $linux = new PlatformProcessRuntimeManagerFake;
    $darwin = new PlatformProcessRuntimeManagerFake;
    $manager = new PlatformProcessRuntimeManager(
        new ProcessTargetResolver,
        linux: $linux->asLinux(),
        darwin: $darwin->asDarwin(),
    );
    $process = platform_runtime_process(platform: 'darwin', runtime: ProcessRuntime::Launchd, user: 'nckrtl');

    $manager->start($process);

    expect($linux->started)->toBeEmpty()->and($darwin->started)->toBe([$process->id]);
});

it('delegates Linux systemd to the Linux manager', function (): void {
    $linux = new PlatformProcessRuntimeManagerFake;
    $darwin = new PlatformProcessRuntimeManagerFake;
    $manager = new PlatformProcessRuntimeManager(
        new ProcessTargetResolver,
        linux: $linux->asLinux(),
        darwin: $darwin->asDarwin(),
    );
    $process = platform_runtime_process(platform: 'linux', runtime: ProcessRuntime::Systemd, user: 'orbit');

    $manager->start($process);

    expect($linux->started)->toBe([$process->id])->and($darwin->started)->toBeEmpty();
});

it('rejects Darwin docker without entering the Linux manager', function (): void {
    $linux = new PlatformProcessRuntimeManagerFake;
    $darwin = new PlatformProcessRuntimeManagerFake;
    $manager = new PlatformProcessRuntimeManager(
        new ProcessTargetResolver,
        linux: $linux->asLinux(),
        darwin: $darwin->asDarwin(),
    );
    $process = platform_runtime_process(platform: 'darwin', runtime: ProcessRuntime::Docker, user: 'nckrtl');

    expect(fn () => $manager->start($process))
        ->toThrow(ProcessOperationException::class, 'not available');

    expect($linux->started)->toBeEmpty()->and($darwin->started)->toBeEmpty();
});

it('rejects Darwin systemd without entering either manager', function (): void {
    $linux = new PlatformProcessRuntimeManagerFake;
    $darwin = new PlatformProcessRuntimeManagerFake;
    $manager = new PlatformProcessRuntimeManager(
        new ProcessTargetResolver,
        linux: $linux->asLinux(),
        darwin: $darwin->asDarwin(),
    );
    $process = platform_runtime_process(platform: 'darwin', runtime: ProcessRuntime::Systemd, user: 'nckrtl');

    expect(fn () => $manager->start($process))
        ->toThrow(ProcessOperationException::class, 'not supported');

    expect($linux->started)->toBeEmpty()->and($darwin->started)->toBeEmpty();
});

it('rejects Linux launchd explicitly', function (): void {
    $linux = new PlatformProcessRuntimeManagerFake;
    $darwin = new PlatformProcessRuntimeManagerFake;
    $manager = new PlatformProcessRuntimeManager(
        new ProcessTargetResolver,
        linux: $linux->asLinux(),
        darwin: $darwin->asDarwin(),
    );
    $process = platform_runtime_process(platform: 'linux', runtime: ProcessRuntime::Launchd, user: 'orbit');

    expect(fn () => $manager->start($process))
        ->toThrow(ProcessOperationException::class, 'not supported');
});

it('keeps persisted environment values out of delegated lifecycle exception traces', function (): void {
    $sentinel = 'platform-dispatch-trace-sentinel';
    $linux = new PlatformProcessRuntimeManagerFake;
    $darwin = new PlatformProcessRuntimeManagerFake;
    $darwin->failStart = true;
    $manager = new PlatformProcessRuntimeManager(
        new ProcessTargetResolver,
        linux: $linux->asLinux(),
        darwin: $darwin->asDarwin(),
    );
    $process = platform_runtime_process(platform: 'darwin', runtime: ProcessRuntime::Launchd, user: 'nckrtl');
    $process->forceFill([
        'runtime_config' => [
            'command' => ['/usr/bin/php', 'artisan', 'queue:work'],
            'environment' => ['TRACE_VALUE' => $sentinel],
        ],
    ])->save();

    $delegatedTrace = null;

    try {
        $manager->start($process);
    } catch (ProcessOperationException $exception) {
        $delegatedTrace = array_values(array_filter(
            $exception->getTrace(),
            static fn (array $frame): bool => (
                is_string($frame['file'] ?? null) && str_starts_with($frame['file'], base_path('app').'/')
            ),
        ));
    }

    expect($delegatedTrace)->toBeArray();
    expect(array_column($delegatedTrace, 'function'))
        ->toContain('start')
        ->and(json_encode($delegatedTrace, JSON_THROW_ON_ERROR))
        ->not->toContain($sentinel);

    $darwin->failStart = false;
    $process->forceFill(['runtime' => ProcessRuntime::Docker])->save();
    $selectionTrace = null;

    try {
        $manager->start($process);
    } catch (ProcessOperationException $exception) {
        $selectionTrace = array_values(array_filter(
            $exception->getTrace(),
            static fn (array $frame): bool => (
                is_string($frame['file'] ?? null) && str_starts_with($frame['file'], base_path('app').'/')
            ),
        ));
    }

    expect($selectionTrace)->toBeArray();
    expect(array_column($selectionTrace, 'function'))
        ->toContain('manager')
        ->and(json_encode($selectionTrace, JSON_THROW_ON_ERROR))
        ->not->toContain($sentinel);
});

it('marks every platform dispatcher process parameter sensitive', function (string $method): void {
    $parameter = new ReflectionMethod(PlatformProcessRuntimeManager::class, $method)->getParameters()[0];

    expect($parameter->getAttributes(SensitiveParameter::class))->toHaveCount(1);
})->with(['converge', 'start', 'stop', 'restart', 'remove', 'status', 'logs', 'manager']);

function platform_runtime_process(string $platform, ProcessRuntime $runtime, string $user): Process
{
    $node = Node::query()->create([
        'name' => "{$platform}-node",
        'status' => LifecycleStatus::Active,
        'platform' => $platform,
        'public_ssh_host' => '192.0.2.20',
        'public_ssh_port' => 22,
        'ssh_user' => $user,
        'wireguard_address' => $platform === 'darwin' ? '10.44.0.9' : '10.44.0.3',
    ]);
    $node->roles()->create([
        'role' => RoleName::AppDev,
        'status' => LifecycleStatus::Active,
    ]);
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
        'checkout_path' => $platform === 'darwin' ? '/Users/nckrtl/apps/docs' : '/home/orbit/apps/docs',
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
        'runtime' => $runtime,
        'working_directory' => $platform === 'darwin' ? '/Users/nckrtl/apps/docs' : '/home/orbit/apps/docs',
        'runtime_config' => ['command' => ['/usr/bin/php', 'artisan', 'queue:work']],
        'restart_policy' => 'always',
        'desired_state' => 'stopped',
        'status' => LifecycleStatus::Active,
    ]);
}

/** @mago-expect lint:file-name Test-local fake keeps the platform dispatch state visible. */
final class PlatformProcessRuntimeManagerFake
{
    /** @var list<int> */
    public array $started = [];

    public bool $failStart = false;

    public function asLinux(): ProcessRuntimeManager
    {
        return new class($this) implements ProcessRuntimeManager {
            public function __construct(
                private PlatformProcessRuntimeManagerFake $fake,
            ) {}

            public function converge(Process $process): void {}

            public function start(Process $process): void
            {
                if ($this->fake->failStart) {
                    throw new ProcessOperationException(
                        step: 'start',
                        errorCode: 'process.start_failed',
                        message: 'The delegated runtime failed.',
                    );
                }

                $this->fake->started[] = $process->id;
            }

            public function stop(Process $process): void {}

            public function restart(Process $process): void {}

            public function remove(Process $process): void {}

            public function status(Process $process): string
            {
                return 'stopped';
            }

            public function logs(Process $process, int $lines): string
            {
                return '';
            }
        };
    }

    public function asDarwin(): ProcessRuntimeManager
    {
        return new class($this) implements ProcessRuntimeManager {
            public function __construct(
                private PlatformProcessRuntimeManagerFake $fake,
            ) {}

            public function converge(Process $process): void {}

            public function start(Process $process): void
            {
                if ($this->fake->failStart) {
                    throw new ProcessOperationException(
                        step: 'start',
                        errorCode: 'process.start_failed',
                        message: 'The delegated runtime failed.',
                    );
                }

                $this->fake->started[] = $process->id;
            }

            public function stop(Process $process): void {}

            public function restart(Process $process): void {}

            public function remove(Process $process): void {}

            public function status(Process $process): string
            {
                return 'stopped';
            }

            public function logs(Process $process, int $lines): string
            {
                return '';
            }
        };
    }
}
