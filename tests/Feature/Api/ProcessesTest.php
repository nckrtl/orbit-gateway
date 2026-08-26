<?php

declare(strict_types=1);

use App\Domain\Processes\ProcessOperationException;
use App\Domain\Processes\ProcessRuntimeManager;
use App\Domain\Shared\LifecycleStatus;
use App\Infrastructure\Processes\CommandResult;
use App\Models\Activity;
use App\Models\App as OrbitApp;
use App\Models\Instance;
use App\Models\Node;
use App\Models\Process;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;
use Monolog\Formatter\LineFormatter;
use Monolog\Handler\TestHandler;
use Monolog\Logger;
use Monolog\LogRecord;
use Psr\Log\LoggerInterface;

beforeEach(function (): void {
    $this->runtime = new ProcessesApiFakeRuntimeManager;
    app()->instance(ProcessRuntimeManager::class, $this->runtime);

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
    $this->node = $node;
    $this->withServerVariables(['REMOTE_ADDR' => $node->wireguard_address]);
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

it('adds and lists a systemd process through the minimal API contract', function (): void {
    $response = $this->postJson('/api/v1/processes', [
        'target_type' => 'instance',
        'target_id' => $this->instance->id,
        'name' => 'queue',
        'runtime' => 'systemd',
        'command' => ['/usr/bin/php', 'artisan', 'queue:work'],
        'restart_policy' => 'on-failure',
        'start' => true,
    ]);

    $response
        ->assertCreated()
        ->assertHeader('X-Orbit-Request-Id')
        ->assertJsonPath('data.target_type', 'instance')
        ->assertJsonPath('data.target_id', $this->instance->id)
        ->assertJsonPath('data.runtime', 'systemd')
        ->assertJsonPath('data.desired_state', 'running')
        ->assertJsonPath('data.runtime_status', 'running')
        ->assertJsonStructure(['meta' => ['request_id']]);
    $process = Process::query()->sole();

    $this->assertDatabaseHas('activity_log', [
        'command' => 'process:add',
        'subject_type' => Process::class,
        'subject_id' => $process->id,
        'target_node_id' => $this->node->id,
        'caller_node_id' => $this->node->id,
        'status' => 'succeeded',
    ]);

    $this
        ->getJson('/api/v1/processes?target_type=instance&target_id='.$this->instance->id)
        ->assertOk()
        ->assertJsonCount(1, 'data')
        ->assertJsonPath('data.0.name', 'queue')
        ->assertJsonPath('data.0.runtime_status', 'running');
});

it('redacts Docker environment values from process responses without changing persisted configuration', function (): void {
    $response = $this->postJson('/api/v1/processes', [
        'target_type' => 'instance',
        'target_id' => $this->instance->id,
        'name' => 'worker',
        'runtime' => 'docker',
        'image' => 'php:8.5-cli',
        'command' => ['php', 'artisan', 'queue:work'],
        'environment' => [
            'APP_ENV' => 'production',
            'APP_KEY' => 'base64:gateway-secret',
            'DATABASE_URL' => 'postgres://orbit:password@example.test/orbit',
        ],
    ]);

    $response
        ->assertCreated()
        ->assertJsonPath('data.runtime_config.environment', [
            'APP_ENV' => '[REDACTED]',
            'APP_KEY' => '[REDACTED]',
            'DATABASE_URL' => '[REDACTED]',
        ]);

    expect($response->getContent())
        ->not->toContain('base64:gateway-secret')
        ->not->toContain('postgres://orbit:password@example.test/orbit');

    $process = Process::query()->sole();

    expect($process->runtime_config['environment'])
        ->toBe([
            'APP_ENV' => 'production',
            'APP_KEY' => 'base64:gateway-secret',
            'DATABASE_URL' => 'postgres://orbit:password@example.test/orbit',
        ]);

    $activity = Activity::query()->where('command', 'process:add')->sole();
    $activityProperties = json_encode($activity->properties, JSON_THROW_ON_ERROR);

    expect(data_get(target: $activity->properties, key: 'input.environment'))
        ->toBe([
            'APP_ENV' => '[REDACTED]',
            'APP_KEY' => '[REDACTED]',
            'DATABASE_URL' => '[REDACTED]',
        ])
        ->and($activityProperties)
        ->not->toContain('base64:gateway-secret')
        ->not->toContain('postgres://orbit:password@example.test/orbit');

    $listResponse = $this
        ->getJson('/api/v1/processes?target_type=instance&target_id='.$this->instance->id)
        ->assertOk()
        ->assertJsonPath('data.0.runtime_config.environment', [
            'APP_ENV' => '[REDACTED]',
            'APP_KEY' => '[REDACTED]',
            'DATABASE_URL' => '[REDACTED]',
        ]);

    expect($listResponse->getContent())
        ->not->toContain('base64:gateway-secret')
        ->not->toContain('postgres://orbit:password@example.test/orbit');
});

it('keeps Docker environment values out of production exception diagnostics', function (): void {
    $sensitiveValue = 'api-boundary-secret';
    $this->runtime->failConverge = true;
    $logHandler = new TestHandler;
    $logHandler->setFormatter(new LineFormatter(includeStacktraces: true));
    app()->instance(LoggerInterface::class, new Logger('testing', [$logHandler]));

    $response = $this
        ->withHeader('X-Orbit-Request-Id', (string) Str::uuid())
        ->postJson('/api/v1/processes', [
            'target_type' => 'instance',
            'target_id' => $this->instance->id,
            'name' => 'worker',
            'runtime' => 'docker',
            'image' => 'php:8.5-cli',
            'command' => ['php', 'artisan', 'queue:work'],
            'environment' => ['APP_KEY' => $sensitiveValue],
        ])
        ->assertStatus(502)
        ->assertJsonPath('error.code', 'process.docker_converge_failed')
        ->assertJsonPath('error.message', 'Docker convergence failed.');
    $activity = Activity::query()->where('command', 'process:add')->sole();
    $activityProperties = json_encode($activity->properties, JSON_THROW_ON_ERROR);
    $exception = $this->runtime->lastConvergeFailure;

    expect(ini_get('zend.exception_ignore_args'))
        ->toBe('1')
        ->and($exception)
        ->toBeInstanceOf(ProcessOperationException::class)
        ->and($exception?->getMessage())
        ->toBe('Docker convergence failed.')
        ->and($exception?->getPrevious()?->getMessage())
        ->toBe('Runtime adapter failed.');

    $appOwnedTrace = array_values(array_filter(
        $exception?->getTrace() ?? [],
        static function (array $frame): bool {
            $file = $frame['file'] ?? null;

            return (
                is_string($file)
                && (
                    str_starts_with($file, base_path('app').DIRECTORY_SEPARATOR)
                    || str_starts_with($file, base_path('bootstrap').DIRECTORY_SEPARATOR)
                )
            );
        },
    ));

    expect($appOwnedTrace)->not->toBeEmpty();

    foreach ($appOwnedTrace as $frame) {
        expect($frame)->not->toHaveKey('args');
    }

    $appOwnedSerializedTrace = json_encode($appOwnedTrace, JSON_THROW_ON_ERROR);
    $formattedLogs = implode('', array_map(
        static fn (LogRecord $record): string => is_string($record->formatted) ? $record->formatted : '',
        $logHandler->getRecords(),
    ));
    $exceptionDiagnostics = json_encode([
        'message' => $exception?->getMessage(),
        'previous' => $exception?->getPrevious()?->getMessage(),
    ], JSON_THROW_ON_ERROR);

    expect(data_get(target: $activity->properties, key: 'input.environment.APP_KEY'))
        ->toBe('[REDACTED]')
        ->and($response->getContent())
        ->not->toContain($sensitiveValue)->and($activityProperties)
        ->not->toContain($sensitiveValue)->and($formattedLogs)
        ->not->toContain($sensitiveValue)->and($exceptionDiagnostics)
        ->not->toContain($sensitiveValue)->and($appOwnedSerializedTrace)
        ->not->toContain($sensitiveValue);
});

it('validates runtime-specific fixed argv and Docker input', function (array $payload, string $field): void {
    $response = $this->postJson('/api/v1/processes', [
        'target_type' => 'instance',
        'target_id' => $this->instance->id,
        'name' => 'worker',
        'runtime' => 'systemd',
        'command' => ['/usr/bin/php', 'artisan'],
        ...$payload,
    ]);

    $response
        ->assertUnprocessable()
        ->assertJsonPath('error.code', 'validation.failed');

    expect($response->json('error.details'))->toHaveKey($field);
})->with([
    'systemd executable must be absolute' => [
        ['command' => ['php', 'artisan']],
        'command.0',
    ],
    'Docker image is explicit' => [
        ['runtime' => 'docker', 'image' => null],
        'image',
    ],
    'Docker image cannot be parsed as a create option' => [
        ['runtime' => 'docker', 'image' => '--privileged'],
        'image',
    ],
    'environment names are safe' => [
        ['runtime' => 'docker', 'image' => 'busybox:1', 'environment' => ['BAD-NAME' => 'value']],
        'environment',
    ],
    'environment values cannot contain a line feed' => [
        ['runtime' => 'docker', 'image' => 'busybox:1', 'environment' => ['APP_KEY' => "first\nsecond"]],
        'environment.APP_KEY',
    ],
    'environment values cannot contain a carriage return' => [
        ['runtime' => 'docker', 'image' => 'busybox:1', 'environment' => ['APP_KEY' => "first\rsecond"]],
        'environment.APP_KEY',
    ],
    'environment values cannot contain a null byte' => [
        ['runtime' => 'docker', 'image' => 'busybox:1', 'environment' => ['APP_KEY' => "first\0second"]],
        'environment.APP_KEY',
    ],
    'port range is bounded' => [
        ['runtime' => 'docker', 'image' => 'busybox:1', 'ports' => ['127.0.0.1:70000:80/tcp']],
        'ports.0',
    ],
    'volume specs cannot inject mount fields' => [
        [
            'runtime' => 'docker',
            'image' => 'busybox:1',
            'volumes' => [['source' => 'data,readonly', 'target' => '/data', 'read_only' => false]],
        ],
        'volumes.0.source',
    ],
]);

it('keeps invalid Docker environment names out of validation and activity diagnostics', function (): void {
    config()->set('app.debug', true);

    $requestId = (string) Str::uuid();
    $sentinel = 'sentinel-invalid-environment-name';
    $invalidName = "BAD\n{$sentinel}\x1B";
    $response = $this
        ->withHeader('X-Orbit-Request-Id', $requestId)
        ->postJson('/api/v1/processes', [
            'target_type' => 'instance',
            'target_id' => $this->instance->id,
            'name' => 'worker',
            'runtime' => 'docker',
            'image' => 'busybox:1',
            'command' => ['env'],
            'environment' => [
                'APP_ENV' => 'production',
                $invalidName => "private\nvalue",
            ],
        ]);

    $response
        ->assertUnprocessable()
        ->assertJsonPath('error.code', 'validation.failed')
        ->assertJsonPath(
            'error.details.environment.0',
            'The environment contains an invalid variable name.',
        );

    $activity = Activity::query()->where('request_id', $requestId)->sole();
    $properties = $activity->properties?->toArray() ?? [];
    $environment = $properties['input']['environment'] ?? null;
    $storedActivityJson = json_encode($activity->getAttributes(), JSON_THROW_ON_ERROR);
    $debugOutput = print_r([
        'response' => $response->json(),
        'activity' => $properties,
        'transport_process_ids' => $this->runtime->convergedProcessIds,
    ], return: true);

    expect($environment)
        ->toBe([
            'APP_ENV' => '[REDACTED]',
            '[INVALID_ENVIRONMENT_NAME]' => '[REDACTED]',
        ])
        ->and($response->getContent())
        ->not->toContain($sentinel)->and($storedActivityJson)
        ->not->toContain($sentinel)->and($debugOutput)
        ->not->toContain($sentinel)->and($this->runtime->convergedProcessIds)->toBeEmpty()->and(
            Process::query()->count(),
        )->toBe(0);

    $serializedActivity = $this
        ->getJson("/api/v1/activities/{$activity->id}")
        ->assertOk()
        ->assertJsonPath('data.properties.input.environment.APP_ENV', '[REDACTED]');

    expect($serializedActivity->json('data.properties.input.environment'))
        ->toBe([
            'APP_ENV' => '[REDACTED]',
            '[INVALID_ENVIRONMENT_NAME]' => '[REDACTED]',
        ])
        ->and($serializedActivity->getContent())
        ->not->toContain($sentinel);
});

it('keeps invalid Docker environment names out of validation exceptions', function (): void {
    $sentinel = 'sentinel-invalid-environment-exception';

    try {
        $this->withoutExceptionHandling()->postJson('/api/v1/processes', [
            'target_type' => 'instance',
            'target_id' => $this->instance->id,
            'name' => 'worker',
            'runtime' => 'docker',
            'image' => 'busybox:1',
            'command' => ['env'],
            'environment' => ["INVALID\r{$sentinel}" => "private\0value"],
        ]);
    } catch (ValidationException $exception) {
        $diagnostics = json_encode([
            'message' => $exception->getMessage(),
            'errors' => $exception->errors(),
        ], JSON_THROW_ON_ERROR);

        expect($diagnostics)
            ->not
            ->toContain($sentinel)
            ->and($exception->errors())
            ->toBe([
                'environment' => ['The environment contains an invalid variable name.'],
            ])
            ->and($this->runtime->convergedProcessIds)
            ->toBeEmpty();

        return;
    }

    $this->fail('Expected invalid environment-name validation to fail.');
});

it('starts stops restarts tails and removes one process', function (): void {
    $process = processes_api_record($this->instance);
    $this->runtime->logs = "first\nsecond\n";

    $this
        ->postJson("/api/v1/processes/{$process->id}/start")
        ->assertOk()
        ->assertJsonPath('data.desired_state', 'running');
    $this
        ->postJson("/api/v1/processes/{$process->id}/stop")
        ->assertOk()
        ->assertJsonPath('data.desired_state', 'stopped');
    $this
        ->postJson("/api/v1/processes/{$process->id}/restart")
        ->assertOk()
        ->assertJsonPath('data.desired_state', 'running');
    $this
        ->getJson("/api/v1/processes/{$process->id}/logs?lines=25")
        ->assertOk()
        ->assertJsonPath('data.lines', 25)
        ->assertJsonPath('data.logs', "first\nsecond\n");
    $this
        ->deleteJson("/api/v1/processes/{$process->id}")
        ->assertOk()
        ->assertJsonPath('data.id', $process->id)
        ->assertJsonPath('data.runtime_status', 'absent');

    expect($this->runtime->logLines)
        ->toBe([25])
        ->and(Process::query()->count())
        ->toBe(0);
});

it('redacts process logs before serializing them to the API response', function (): void {
    $process = processes_api_record($this->instance);
    $this->runtime->logs = "token=base64:gateway-secret\npassword=super-secret\n";

    $response = $this
        ->getJson("/api/v1/processes/{$process->id}/logs?lines=25")
        ->assertOk()
        ->assertJsonPath('data.logs', "token=[REDACTED]\npassword=[REDACTED]\n");

    expect($response->getContent())
        ->not->toContain('base64:gateway-secret')
        ->not->toContain('super-secret');
});

it('redacts configured Docker environment values even when logs omit their names', function (): void {
    $process = processes_api_record($this->instance);
    $process->forceFill([
        'runtime' => 'docker',
        'runtime_config' => [
            'image' => 'busybox:1',
            'command' => ['env'],
            'environment' => [
                'SHORT_VALUE' => 'opaque',
                'LONG_VALUE' => 'opaque-value',
            ],
        ],
    ])->save();
    $this->runtime->logs = "worker output opaque-value\nworker output opaque\n";

    $response = $this
        ->getJson("/api/v1/processes/{$process->id}/logs?lines=25")
        ->assertOk()
        ->assertJsonPath('data.logs', "worker output [REDACTED]\nworker output [REDACTED]\n");

    expect($response->getContent())
        ->not->toContain('opaque-value')
        ->not->toContain('opaque');
});

it('bounds process log requests and does not support follow mode', function (): void {
    $process = processes_api_record($this->instance);

    $response = $this->getJson("/api/v1/processes/{$process->id}/logs?lines=1001&follow=true");

    $response
        ->assertUnprocessable()
        ->assertJsonPath('error.code', 'validation.failed');

    expect($response->json('error.details'))
        ->toHaveKeys(['lines', 'follow']);
});

it('redacts secrets from bounded process logs before serialization', function (): void {
    $process = processes_api_record($this->instance);
    $this->runtime->logs = implode("\n", [
        'worker started',
        'APP_KEY=base64:gateway-secret',
        'Authorization: Bearer abcdefghijklmnop',
        'DATABASE_PASSWORD=database-secret',
    ]);

    $response = $this
        ->getJson("/api/v1/processes/{$process->id}/logs?lines=25")
        ->assertOk()
        ->assertJsonPath('data.logs', implode("\n", [
            'worker started',
            'APP_KEY=[REDACTED]',
            'Authorization: [REDACTED]',
            'DATABASE_PASSWORD=[REDACTED]',
        ]));

    expect($response->getContent())
        ->not->toContain('base64:gateway-secret')
        ->not->toContain('abcdefghijklmnop')
        ->not->toContain('database-secret');
});

it('records a failed runtime action against its process and target node', function (): void {
    $process = processes_api_record($this->instance);
    $this->runtime->startFailure = new ProcessOperationException(
        step: 'start',
        errorCode: 'process.start_failed',
        message: 'The process did not start.',
        result: new CommandResult(1, '', 'service failed', 12, false),
    );

    $this
        ->postJson("/api/v1/processes/{$process->id}/start")
        ->assertStatus(502)
        ->assertJsonPath('error.code', 'process.start_failed')
        ->assertJsonPath('error.details.step', 'start');

    $activity = Activity::query()->where('command', 'process:start')->sole();

    expect($activity->subject_type)
        ->toBe(Process::class)
        ->and($activity->subject_id)
        ->toBe($process->id)
        ->and($activity->target_node_id)
        ->toBe($this->node->id)
        ->and($activity->status)
        ->toBe('failed')
        ->and($activity->error_code)
        ->toBe('process.start_failed');
});

it('redacts configured Docker environment values from failed runtime activity output', function (): void {
    $process = processes_api_record($this->instance);
    $process->forceFill([
        'runtime' => 'docker',
        'runtime_config' => [
            'image' => 'busybox:1',
            'command' => ['env'],
            'environment' => ['APP_KEY' => 'opaque-runtime-secret'],
        ],
    ])->save();
    $this->runtime->startFailure = new ProcessOperationException(
        step: 'start',
        errorCode: 'process.start_failed',
        message: 'The process did not start.',
        result: new CommandResult(1, '', 'remote failed: opaque-runtime-secret', 12, false),
    );

    $response = $this
        ->postJson("/api/v1/processes/{$process->id}/start")
        ->assertStatus(502)
        ->assertJsonPath('error.code', 'process.start_failed');
    $activity = Activity::query()->where('command', 'process:start')->sole();
    $activityProperties = json_encode($activity->properties, JSON_THROW_ON_ERROR);

    expect($response->getContent())
        ->not->toContain('opaque-runtime-secret')->and($activityProperties)
        ->not->toContain('opaque-runtime-secret')->toContain('remote failed: [REDACTED]');
});

it('keeps persisted Docker environment values out of lifecycle exception traces', function (): void {
    $sensitiveValue = 'lifecycle-boundary-secret';
    $process = processes_api_record($this->instance);
    $process->forceFill([
        'runtime' => 'docker',
        'runtime_config' => [
            'image' => 'busybox:1',
            'command' => ['env'],
            'environment' => ['APP_KEY' => $sensitiveValue],
        ],
    ])->save();
    $this->runtime->failStartDuringCall = true;

    try {
        $this->withoutExceptionHandling()->postJson("/api/v1/processes/{$process->id}/start");
    } catch (ProcessOperationException $exception) {
        $productionTrace = array_values(array_filter(
            $exception->getTrace(),
            static function (array $frame): bool {
                $file = $frame['file'] ?? '';

                return (
                    is_string($file)
                    && ! str_starts_with($file, base_path('tests').'/')
                    && ! str_contains($file, '/Illuminate/Foundation/Testing/')
                );
            },
        ));

        expect(json_encode($productionTrace, JSON_THROW_ON_ERROR))
            ->not->toContain($sensitiveValue)->and(print_r($process, return: true))
            ->not->toContain($sensitiveValue);

        return;
    }

    $this->fail('Expected process start to fail.');
});

function processes_api_record(Instance $instance): Process
{
    return Process::query()->create([
        'owner_type' => Instance::class,
        'owner_id' => $instance->id,
        'name' => 'queue',
        'runtime' => 'systemd',
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

/** @mago-expect lint:file-name Test-local fake keeps the API scenario setup visible. */
final class ProcessesApiFakeRuntimeManager implements ProcessRuntimeManager
{
    /** @var list<int> */
    public array $convergedProcessIds = [];

    /** @var list<int> */
    public array $logLines = [];

    public string $logs = '';

    public ?ProcessOperationException $startFailure = null;

    public bool $failConverge = false;

    public bool $failStartDuringCall = false;

    public ?ProcessOperationException $lastConvergeFailure = null;

    public function converge(#[SensitiveParameter] Process $process): void
    {
        $this->convergedProcessIds[] = (int) $process->getKey();

        if ($this->failConverge) {
            $this->lastConvergeFailure = new ProcessOperationException(
                step: 'create-container',
                errorCode: 'process.docker_converge_failed',
                message: 'Docker convergence failed.',
                previous: new RuntimeException('Runtime adapter failed.'),
            );

            throw $this->lastConvergeFailure;
        }
    }

    public function start(#[SensitiveParameter] Process $process): void
    {
        if ($this->failStartDuringCall) {
            throw new ProcessOperationException(
                step: 'start',
                errorCode: 'process.start_failed',
                message: 'The process did not start.',
            );
        }

        if ($this->startFailure instanceof ProcessOperationException) {
            throw $this->startFailure;
        }
    }

    public function stop(Process $process): void {}

    public function restart(Process $process): void {}

    public function remove(Process $process): void {}

    public function status(Process $process): string
    {
        return $process->exists
            ? $process->desired_state->value
            : 'absent';
    }

    public function logs(Process $process, int $lines): string
    {
        $this->logLines[] = $lines;

        return $this->logs;
    }
}
