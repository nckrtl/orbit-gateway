<?php

declare(strict_types=1);

namespace App\Domain\Tools;

use App\Infrastructure\Processes\CommandResult;
use RuntimeException;
use Throwable;

final class ToolManagerException extends RuntimeException
{
    public readonly ?CommandResult $result;

    public function __construct(
        public readonly string $step,
        string $message,
        ?CommandResult $result = null,
        ?Throwable $previous = null,
    ) {
        $this->result = $result === null
            ? null
            : new CommandResult(
                exitCode: $result->exitCode,
                stdout: '',
                stderr: '',
                durationMs: $result->durationMs,
                truncated: $result->truncated,
            );

        parent::__construct($message, previous: $previous);
    }

    /** @return array{message: string, step: string, result: array{exitCode: int, durationMs: int, truncated: bool}|null} */
    public function __debugInfo(): array
    {
        return [
            'message' => $this->getMessage(),
            'step' => $this->step,
            'result' => $this->result === null
                ? null
                : [
                    'exitCode' => $this->result->exitCode,
                    'durationMs' => $this->result->durationMs,
                    'truncated' => $this->result->truncated,
                ],
        ];
    }
}
