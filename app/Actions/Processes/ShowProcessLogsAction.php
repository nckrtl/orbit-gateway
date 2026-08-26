<?php

declare(strict_types=1);

namespace App\Actions\Processes;

use App\Domain\Processes\ProcessRuntimeManager;
use App\Infrastructure\Activity\CommandActivityInputSanitizer;
use App\Models\Process;
use SensitiveParameter;

final readonly class ShowProcessLogsAction
{
    public function __construct(
        private ProcessRuntimeManager $runtime,
        private CommandActivityInputSanitizer $sanitizer,
    ) {}

    public function execute(#[SensitiveParameter] Process $process, int $lines): string
    {
        $logs = $this->redactEnvironmentValues(
            $process,
            $this->runtime->logs($process, $lines),
        );

        return $this->sanitizer->redactText($logs);
    }

    /** @mago-expect analysis:mixed-assignment Persisted runtime configuration starts at an untyped boundary. */
    private function redactEnvironmentValues(
        #[SensitiveParameter]
        Process $process,
        #[SensitiveParameter]
        string $logs,
    ): string {
        $environment = $process->runtime_config['environment'] ?? null;

        if (! is_array($environment)) {
            return $logs;
        }

        $values = [];

        foreach ($environment as $value) {
            if (! is_string($value) || $value === '') {
                continue;
            }

            $values[] = $value;
        }

        $values = array_values(array_unique($values));
        usort($values, static fn (string $first, string $second): int => strlen($second) <=> strlen($first));

        return str_replace(search: $values, replace: '[REDACTED]', subject: $logs);
    }
}
