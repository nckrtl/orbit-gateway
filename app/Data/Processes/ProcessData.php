<?php

declare(strict_types=1);

namespace App\Data\Processes;

use App\Domain\Processes\ProcessTargetType;
use App\Models\Process;
use SensitiveParameter;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\SnakeCaseMapper;

/** @mago-expect lint:excessive-parameter-list */
#[MapOutputName(SnakeCaseMapper::class)]
final class ProcessData extends Data
{
    /** @param array<string, mixed> $runtimeConfig */
    public function __construct(
        public int $id,
        public string $targetType,
        public int $targetId,
        public string $name,
        public string $runtime,
        public string $workingDirectory,
        public array $runtimeConfig,
        public string $restartPolicy,
        public string $desiredState,
        public string $status,
        public string $runtimeStatus,
        public ?string $failedStep,
        public ?string $errorCode,
    ) {}

    public static function fromModel(#[SensitiveParameter] Process $process, string $runtimeStatus): self
    {
        /** @var ?string $failedStep */
        $failedStep = $process->getAttribute('failed_step');
        /** @var ?string $errorCode */
        $errorCode = $process->getAttribute('error_code');

        return new self(
            id: $process->id,
            targetType: ProcessTargetType::fromModelClass($process->owner_type)->value,
            targetId: $process->owner_id,
            name: $process->name,
            runtime: $process->runtime->value,
            workingDirectory: $process->working_directory,
            runtimeConfig: self::redactedRuntimeConfig($process),
            restartPolicy: $process->restart_policy,
            desiredState: $process->desired_state->value,
            status: $process->status->value,
            runtimeStatus: $runtimeStatus,
            failedStep: $failedStep,
            errorCode: $errorCode,
        );
    }

    /**
     * @return array<string, mixed>
     *
     * @mago-expect analysis:mixed-assignment Persisted JSON values start at an untyped boundary.
     */
    private static function redactedRuntimeConfig(#[SensitiveParameter] Process $process): array
    {
        $runtimeConfig = $process->runtime_config;
        $environment = $runtimeConfig['environment'] ?? null;

        if (! is_array($environment)) {
            return $runtimeConfig;
        }

        $runtimeConfig['environment'] = array_fill_keys(
            keys: array_keys($environment),
            value: '[REDACTED]',
        );

        return $runtimeConfig;
    }
}
