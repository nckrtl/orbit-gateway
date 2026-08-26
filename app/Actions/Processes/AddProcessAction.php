<?php

declare(strict_types=1);

namespace App\Actions\Processes;

use App\Data\Processes\AddProcessData;
use App\Domain\Processes\DesiredProcessState;
use App\Domain\Processes\ProcessOperationException;
use App\Domain\Processes\ProcessRuntime;
use App\Domain\Processes\ProcessRuntimeManager;
use App\Domain\Processes\ProcessTarget;
use App\Domain\Processes\ProcessTargetResolver;
use App\Domain\Shared\LifecycleStatus;
use App\Domain\Shared\ResourceOperationException;
use App\Models\Process;
use SensitiveParameter;

final readonly class AddProcessAction
{
    public function __construct(
        private ProcessTargetResolver $targets,
        private ProcessRuntimeManager $runtime,
    ) {}

    /** @return array{process: Process, created: bool} */
    public function execute(#[SensitiveParameter] AddProcessData $data): array
    {
        $target = $this->targets->resolve($data->targetType, $data->targetId);
        $attributes = $this->attributes($data, $target);
        $process = Process::query()->firstOrNew([
            'owner_type' => $data->targetType->modelClass(),
            'owner_id' => $data->targetId,
            'name' => $data->name,
        ]);
        $created = ! $process->exists;
        $desiredState = $process->desired_state;

        if ($created) {
            $desiredState = $data->start ? DesiredProcessState::Running : DesiredProcessState::Stopped;
        }

        if ($process->exists && ! $this->matches($process, $attributes)) {
            throw new ResourceOperationException(
                errorCode: 'process.name_taken',
                message: "Process [{$data->name}] already exists with different configuration.",
                status: 409,
            );
        }

        $process->fill([
            ...$attributes,
            'desired_state' => $desiredState,
            'status' => LifecycleStatus::Provisioning,
            'failed_step' => null,
            'error_code' => null,
        ])->save();

        try {
            $this->runtime->converge($process);
        } catch (ProcessOperationException $exception) {
            $process->update([
                'status' => LifecycleStatus::Failed,
                'failed_step' => $exception->step,
                'error_code' => $exception->errorCode,
            ]);

            throw $exception;
        }

        $process->update([
            'status' => LifecycleStatus::Active,
            'failed_step' => null,
            'error_code' => null,
        ]);

        return ['process' => $process->refresh(), 'created' => $created];
    }

    /** @return array{runtime: ProcessRuntime, working_directory: string, runtime_config: array<string, mixed>, restart_policy: string} */
    private function attributes(#[SensitiveParameter] AddProcessData $data, ProcessTarget $target): array
    {
        $workingDirectory =
            $data->workingDirectory ?? ($data->runtime === ProcessRuntime::Systemd ? $target->checkoutPath : '/app');
        $runtimeConfig = $data->runtime === ProcessRuntime::Systemd
            ? [
                'command' => $data->command,
                'environment_file' => "{$target->checkoutPath}/.env",
            ]
            : [
                'image' => $data->image,
                'command' => $data->command,
                'environment' => $data->environment,
                'ports' => $data->ports,
                'volumes' => $data->volumes,
            ];
        $runtimeConfig = $this->canonicalRuntimeConfig($data->runtime, $runtimeConfig);

        return [
            'runtime' => $data->runtime,
            'working_directory' => $workingDirectory,
            'runtime_config' => $runtimeConfig,
            'restart_policy' => $data->restartPolicy,
        ];
    }

    /** @param array{runtime: ProcessRuntime, working_directory: string, runtime_config: array<string, mixed>, restart_policy: string} $attributes */
    private function matches(
        #[SensitiveParameter]
        Process $process,
        #[SensitiveParameter]
        array $attributes,
    ): bool {
        return (
            $process->runtime === $attributes['runtime']
            && $process->working_directory === $attributes['working_directory']
            && $this->canonicalRuntimeConfig($process->runtime, $process->runtime_config)
            === $attributes['runtime_config']
            && $process->restart_policy === $attributes['restart_policy']
        );
    }

    /**
     * @param array<string, mixed> $runtimeConfig
     * @return array<string, mixed>
     *
     * @mago-expect analysis:mixed-assignment Persisted JSON values start at an untyped boundary.
     */
    private function canonicalRuntimeConfig(
        ProcessRuntime $runtime,
        #[SensitiveParameter]
        array $runtimeConfig,
    ): array {
        if ($runtime !== ProcessRuntime::Docker) {
            return $runtimeConfig;
        }

        $environment = $runtimeConfig['environment'] ?? [];

        if (! is_array($environment)) {
            return $runtimeConfig;
        }

        ksort($environment);
        $runtimeConfig['environment'] = $environment;

        return $runtimeConfig;
    }
}
