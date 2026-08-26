<?php

declare(strict_types=1);

use App\Actions\Processes\AddProcessAction;
use App\Actions\Processes\ListProcessesAction;
use App\Actions\Processes\RemoveProcessAction;
use App\Actions\Processes\RestartProcessAction;
use App\Actions\Processes\ShowProcessLogsAction;
use App\Actions\Processes\StartProcessAction;
use App\Actions\Processes\StopProcessAction;
use App\Data\Processes\AddProcessData;
use App\Domain\Nodes\RoleName;
use App\Domain\Processes\DesiredProcessState;
use App\Domain\Processes\ProcessOperationException;
use App\Domain\Processes\ProcessRuntime;
use App\Domain\Processes\ProcessRuntimeManager;
use App\Domain\Processes\ProcessTargetResolver;
use App\Domain\Processes\ProcessTargetType;
use App\Domain\Shared\LifecycleStatus;
use App\Domain\Shared\ResourceOperationException;
use App\Infrastructure\Activity\CommandActivityInputSanitizer;
use App\Models\App as OrbitApp;
use App\Models\Instance;
use App\Models\Node;
use App\Models\Process;
use App\Models\Workspace;

beforeEach(function (): void {
    $this->runtime = new ProcessActionsFakeRuntimeManager;
    app()->instance(ProcessRuntimeManager::class, $this->runtime);
    $this->targets = new ProcessTargetResolver;

    $this->node = Node::query()->create([
        'name' => 'app-dev',
        'status' => LifecycleStatus::Active,
        'platform' => 'linux',
        'public_ssh_host' => '192.0.2.20',
        'public_ssh_port' => 22,
        'ssh_user' => 'orbit',
        'wireguard_address' => '10.44.0.3',
    ]);
    $this->node
        ->roles()
        ->create([
            'role' => RoleName::AppDev,
            'status' => LifecycleStatus::Active,
        ]);
    $this->orbitApp = OrbitApp::query()->create([
        'name' => 'Docs',
        'slug' => 'docs',
        'repository_url' => 'git@example.test:docs.git',
    ]);
    $this->instance = Instance::query()->create([
        'app_id' => $this->orbitApp->id,
        'node_id' => $this->node->id,
        'name' => 'main',
        'environment' => 'development',
        'checkout_path' => '/home/orbit/apps/docs',
        'document_root' => 'public',
        'php_version' => '8.5',
        'hostname' => 'docs.app-dev.orbit',
        'certificate_mode' => 'orbit-ca',
        'status' => LifecycleStatus::Active,
    ]);
    $this->workspace = Workspace::query()->create([
        'instance_id' => $this->instance->id,
        'name' => 'feature',
        'branch' => 'feature',
        'checkout_path' => '/home/orbit/.orbit/worktrees/docs/feature',
        'hostname' => 'feature.docs.app-dev.orbit',
        'status' => LifecycleStatus::Active,
    ]);
});

it('adds a stopped systemd process idempotently with the target defaults', function (): void {
    $data = new AddProcessData(
        targetType: ProcessTargetType::Instance,
        targetId: $this->instance->id,
        name: 'queue',
        runtime: ProcessRuntime::Systemd,
        command: ['/usr/bin/php', 'artisan', 'queue:work'],
        image: null,
        workingDirectory: null,
        environment: [],
        ports: [],
        volumes: [],
        restartPolicy: 'on-failure',
        start: false,
    );
    $action = new AddProcessAction($this->targets, $this->runtime);

    $first = $action->execute($data);
    $second = $action->execute($data);
    $process = $first['process'];

    expect($first['created'])
        ->toBeTrue()
        ->and($second['created'])
        ->toBeFalse()
        ->and(Process::query()->count())
        ->toBe(1)
        ->and($process->working_directory)
        ->toBe('/home/orbit/apps/docs')
        ->and($process->runtime_config)
        ->toBe([
            'command' => ['/usr/bin/php', 'artisan', 'queue:work'],
            'environment_file' => '/home/orbit/apps/docs/.env',
        ])
        ->and($process->desired_state->value)
        ->toBe('stopped')
        ->and($process->status)
        ->toBe(LifecycleStatus::Active)
        ->and($this->runtime->converged)
        ->toBe([
            ['id' => $process->id, 'desired_state' => 'stopped'],
            ['id' => $process->id, 'desired_state' => 'stopped'],
        ])
        ->and($this->runtime->started)
        ->toBeEmpty();
});

it('preserves the desired state when an existing process is added again', function (): void {
    $process = process_actions_record($this->instance);
    $process->update(['desired_state' => 'running']);
    $data = new AddProcessData(
        targetType: ProcessTargetType::Instance,
        targetId: $this->instance->id,
        name: 'queue',
        runtime: ProcessRuntime::Systemd,
        command: ['/usr/bin/php', 'artisan', 'queue:work'],
        image: null,
        workingDirectory: null,
        environment: [],
        ports: [],
        volumes: [],
        restartPolicy: 'always',
        start: false,
    );

    $result = new AddProcessAction($this->targets, $this->runtime)->execute($data);

    expect($result['created'])
        ->toBeFalse()
        ->and($result['process']->desired_state->value)
        ->toBe('running')
        ->and($this->runtime->started)
        ->toBeEmpty();
});

it('canonicalizes Docker environment maps before persistence and idempotency comparison', function (): void {
    $action = new AddProcessAction($this->targets, $this->runtime);
    $first = new AddProcessData(
        targetType: ProcessTargetType::Instance,
        targetId: $this->instance->id,
        name: 'worker',
        runtime: ProcessRuntime::Docker,
        command: ['php', 'artisan', 'queue:work'],
        image: 'php:8.5-cli',
        workingDirectory: '/app',
        environment: ['ZEBRA' => 'last', 'APP_KEY' => 'secret', 'ALPHA' => 'first'],
        ports: [],
        volumes: [],
        restartPolicy: 'unless-stopped',
        start: false,
    );
    $sameWithDifferentOrder = new AddProcessData(
        targetType: ProcessTargetType::Instance,
        targetId: $this->instance->id,
        name: 'worker',
        runtime: ProcessRuntime::Docker,
        command: ['php', 'artisan', 'queue:work'],
        image: 'php:8.5-cli',
        workingDirectory: '/app',
        environment: ['ALPHA' => 'first', 'ZEBRA' => 'last', 'APP_KEY' => 'secret'],
        ports: [],
        volumes: [],
        restartPolicy: 'unless-stopped',
        start: false,
    );

    $created = $action->execute($first);
    $readded = $action->execute($sameWithDifferentOrder);

    expect($created['process']->runtime_config['environment'])
        ->toBe(['ALPHA' => 'first', 'APP_KEY' => 'secret', 'ZEBRA' => 'last'])
        ->and($readded['created'])
        ->toBeFalse()
        ->and(Process::query()->count())
        ->toBe(1);
});

it('keeps Docker environment values out of action exception traces', function (): void {
    $sensitiveValue = 'action-boundary-secret';
    $data = new AddProcessData(
        targetType: ProcessTargetType::Instance,
        targetId: $this->instance->id,
        name: 'worker',
        runtime: ProcessRuntime::Docker,
        command: ['php', 'artisan', 'queue:work'],
        image: 'php:8.5-cli',
        workingDirectory: '/app',
        environment: ['APP_KEY' => $sensitiveValue],
        ports: [],
        volumes: [],
        restartPolicy: 'unless-stopped',
        start: false,
    );
    $this->runtime->startFailure = new ProcessOperationException(
        step: 'create-container',
        errorCode: 'process.docker_converge_failed',
        message: 'Docker convergence failed.',
    );

    try {
        new AddProcessAction($this->targets, $this->runtime)->execute($data);
    } catch (ProcessOperationException $exception) {
        expect(json_encode($exception->getTrace(), JSON_THROW_ON_ERROR))->not->toContain($sensitiveValue);

        return;
    }

    $this->fail('Expected Docker convergence to fail.');
});

it('adds and starts one Docker container process with explicit configuration', function (): void {
    $data = new AddProcessData(
        targetType: ProcessTargetType::Workspace,
        targetId: $this->workspace->id,
        name: 'redis',
        runtime: ProcessRuntime::Docker,
        command: ['redis-server'],
        image: 'redis:8-alpine',
        workingDirectory: '/data',
        environment: ['APP_MODE' => 'test'],
        ports: ['127.0.0.1:6380:6379/tcp'],
        volumes: [['source' => 'redis-data', 'target' => '/data', 'read_only' => false]],
        restartPolicy: 'unless-stopped',
        start: true,
    );

    $result = new AddProcessAction($this->targets, $this->runtime)->execute($data);
    $process = $result['process'];

    expect($process->owner)
        ->toBeInstanceOf(Workspace::class)
        ->and($process->runtime_config)
        ->toBe([
            'image' => 'redis:8-alpine',
            'command' => ['redis-server'],
            'environment' => ['APP_MODE' => 'test'],
            'ports' => ['127.0.0.1:6380:6379/tcp'],
            'volumes' => [['source' => 'redis-data', 'target' => '/data', 'read_only' => false]],
        ])
        ->and($process->desired_state->value)
        ->toBe('running')
        ->and($this->runtime->converged)
        ->toBe([['id' => $process->id, 'desired_state' => 'running']])
        ->and($this->runtime->started)
        ->toBeEmpty();
});

it('retains a failed desired-running process definition and clears recovery state on retry', function (): void {
    $data = new AddProcessData(
        targetType: ProcessTargetType::Instance,
        targetId: $this->instance->id,
        name: 'worker',
        runtime: ProcessRuntime::Docker,
        command: ['php', 'artisan', 'queue:work'],
        image: 'php:8.5-cli',
        workingDirectory: '/app',
        environment: ['APP_ENV' => 'production'],
        ports: [],
        volumes: [],
        restartPolicy: 'unless-stopped',
        start: true,
    );
    $action = new AddProcessAction($this->targets, $this->runtime);
    $this->runtime->startFailure = new ProcessOperationException(
        step: 'start',
        errorCode: 'process.start_failed',
        message: 'The replacement did not start; the previous container was restored.',
    );

    expect(fn () => $action->execute($data))
        ->toThrow(ProcessOperationException::class, 'previous container was restored');

    $failed = Process::query()->sole();

    expect($failed)
        ->desired_state->toBe(DesiredProcessState::Running)
        ->status->toBe(LifecycleStatus::Failed)
        ->failed_step->toBe('start')
        ->error_code->toBe('process.start_failed');

    $this->runtime->startFailure = null;
    $retryResult = $action->execute($data);
    $retried = $retryResult['process'];

    expect($retried)
        ->id->toBe($failed->id)
        ->desired_state->toBe(DesiredProcessState::Running)
        ->status->toBe(LifecycleStatus::Active)
        ->failed_step->toBeNull()
        ->error_code->toBeNull()->and($retryResult['created'])->toBeFalse()->and(Process::query()->count())->toBe(
            1,
        )->and($this->runtime->started)->toBeEmpty();
});

it('rejects a conflicting process definition with the same owner and name', function (): void {
    $action = new AddProcessAction($this->targets, $this->runtime);
    $initial = new AddProcessData(
        targetType: ProcessTargetType::Instance,
        targetId: $this->instance->id,
        name: 'queue',
        runtime: ProcessRuntime::Systemd,
        command: ['/usr/bin/php', 'artisan', 'queue:work'],
        image: null,
        workingDirectory: null,
        environment: [],
        ports: [],
        volumes: [],
        restartPolicy: 'always',
        start: true,
    );
    $changed = new AddProcessData(
        targetType: ProcessTargetType::Instance,
        targetId: $this->instance->id,
        name: 'queue',
        runtime: ProcessRuntime::Systemd,
        command: ['/usr/bin/php', 'artisan', 'queue:listen'],
        image: null,
        workingDirectory: null,
        environment: [],
        ports: [],
        volumes: [],
        restartPolicy: 'always',
        start: true,
    );
    $action->execute($initial);

    expect(fn () => $action->execute($changed))
        ->toThrow(ResourceOperationException::class, 'already exists with different configuration');
});

it('uses an isolated app user for app-prod systemd processes', function (): void {
    $this->node->roles()->delete();
    $this->node
        ->roles()
        ->create([
            'role' => RoleName::AppProd,
            'status' => LifecycleStatus::Active,
        ]);

    $target = $this->targets->resolve(ProcessTargetType::Instance, $this->instance->id);

    expect($target->user)->toBe('orbit-docs');
});

it('rejects workspace process targets on app-prod nodes', function (): void {
    $this->node->roles()->delete();
    $this->node
        ->roles()
        ->create([
            'role' => RoleName::AppProd,
            'status' => LifecycleStatus::Active,
        ]);

    expect(fn () => $this->targets->resolve(ProcessTargetType::Workspace, $this->workspace->id))
        ->toThrow(ResourceOperationException::class, 'Workspaces cannot run processes on app-prod nodes.');
});

it('rejects process targets on non-Linux nodes before runtime execution', function (): void {
    $this->node->update(['platform' => 'darwin']);
    $data = new AddProcessData(
        targetType: ProcessTargetType::Instance,
        targetId: $this->instance->id,
        name: 'queue',
        runtime: ProcessRuntime::Systemd,
        command: ['/usr/bin/php', 'artisan', 'queue:work'],
        image: null,
        workingDirectory: null,
        environment: [],
        ports: [],
        volumes: [],
        restartPolicy: 'always',
        start: false,
    );

    try {
        new AddProcessAction($this->targets, $this->runtime)->execute($data);
    } catch (ResourceOperationException $exception) {
        expect($exception->errorCode)
            ->toBe('process.platform_unsupported')
            ->and(Process::query()->count())
            ->toBe(0)
            ->and($this->runtime->converged)
            ->toBeEmpty();

        return;
    }

    $this->fail('Expected a non-Linux process target to be rejected.');
});

it('runs idempotent lifecycle actions and returns bounded logs', function (): void {
    $process = process_actions_record($this->instance);
    $this->runtime->status = 'running';
    $this->runtime->logs = "one\ntwo\n";

    $started = new StartProcessAction($this->runtime)->execute($process);
    $startedState = $started->desired_state->value;
    $stopped = new StopProcessAction($this->runtime)->execute($process);
    $stoppedState = $stopped->desired_state->value;
    $restarted = new RestartProcessAction($this->runtime)->execute($process);
    $restartedState = $restarted->desired_state->value;
    $logs = new ShowProcessLogsAction($this->runtime, new CommandActivityInputSanitizer)->execute($process, 25);

    expect($this->runtime->started)
        ->toBe([$process->id])
        ->and($this->runtime->stopped)
        ->toBe([$process->id])
        ->and($this->runtime->restarted)
        ->toBe([$process->id])
        ->and($this->runtime->logLines)
        ->toBe([25])
        ->and($startedState)
        ->toBe('running')
        ->and($stoppedState)
        ->toBe('stopped')
        ->and($restartedState)
        ->toBe('running')
        ->and($logs)
        ->toBe("one\ntwo\n");
});

it('lists runtime status and removes only the selected process', function (): void {
    $process = process_actions_record($this->instance);
    $this->runtime->status = 'stopped';

    $listed = new ListProcessesAction($this->runtime)->execute(
        ProcessTargetType::Instance,
        $this->instance->id,
    );
    $removed = new RemoveProcessAction($this->runtime)->execute($process);

    expect($listed)
        ->toHaveCount(1)
        ->and($listed->first()['runtime_status'])
        ->toBe('stopped')
        ->and($removed->exists)
        ->toBeFalse()
        ->and($this->runtime->removed)
        ->toBe([$process->id])
        ->and(Process::query()->count())
        ->toBe(0);
});

it('records stable lifecycle failure state without losing the process definition', function (): void {
    $process = process_actions_record($this->instance);
    $this->runtime->startFailure = new ProcessOperationException(
        step: 'start',
        errorCode: 'process.start_failed',
        message: 'Start failed.',
    );

    expect(fn () => new StartProcessAction($this->runtime)->execute($process))
        ->toThrow(ProcessOperationException::class, 'Start failed.');

    expect($process->refresh())
        ->status->toBe(LifecycleStatus::Failed)
        ->failed_step->toBe('start')
        ->error_code->toBe('process.start_failed')->and(Process::query()->count())->toBe(1);
});

it('retains the process definition when runtime removal fails', function (): void {
    $process = process_actions_record($this->instance);
    $this->runtime->removeFailure = new ProcessOperationException(
        step: 'stop',
        errorCode: 'process.remove_failed',
        message: 'The owned unit could not be stopped.',
    );

    expect(fn () => new RemoveProcessAction($this->runtime)->execute($process))
        ->toThrow(ProcessOperationException::class, 'could not be stopped');

    expect($process->refresh())
        ->status->toBe(LifecycleStatus::Failed)
        ->failed_step->toBe('stop')
        ->error_code->toBe('process.remove_failed')->and(Process::query()->count())->toBe(1);
});

function process_actions_record(Instance $instance): Process
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

/** @mago-expect lint:file-name Test-local fake keeps the lifecycle assertions visible. */
final class ProcessActionsFakeRuntimeManager implements ProcessRuntimeManager
{
    /** @var list<array{id: int, desired_state: string}> */
    public array $converged = [];

    /** @var list<int> */
    public array $started = [];

    /** @var list<int> */
    public array $stopped = [];

    /** @var list<int> */
    public array $restarted = [];

    /** @var list<int> */
    public array $removed = [];

    /** @var list<int> */
    public array $logLines = [];

    public string $status = 'stopped';

    public string $logs = '';

    public ?ProcessOperationException $startFailure = null;

    public ?ProcessOperationException $removeFailure = null;

    public function converge(#[SensitiveParameter] Process $process): void
    {
        if ($this->startFailure instanceof ProcessOperationException) {
            throw new ProcessOperationException(
                step: $this->startFailure->step,
                errorCode: $this->startFailure->errorCode,
                message: $this->startFailure->getMessage(),
            );
        }

        $this->converged[] = [
            'id' => $process->id,
            'desired_state' => $process->desired_state->value,
        ];
    }

    public function start(Process $process): void
    {
        if ($this->startFailure instanceof ProcessOperationException) {
            throw $this->startFailure;
        }

        $this->started[] = $process->id;
    }

    public function stop(Process $process): void
    {
        $this->stopped[] = $process->id;
    }

    public function restart(Process $process): void
    {
        $this->restarted[] = $process->id;
    }

    public function remove(Process $process): void
    {
        if ($this->removeFailure instanceof ProcessOperationException) {
            throw $this->removeFailure;
        }

        $this->removed[] = $process->id;
    }

    public function status(Process $process): string
    {
        return $this->status;
    }

    public function logs(Process $process, int $lines): string
    {
        $this->logLines[] = $lines;

        return $this->logs;
    }
}
