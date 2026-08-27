<?php

declare(strict_types=1);

namespace App\Domain\Nodes;

use App\Infrastructure\Processes\CommandResult;
use RuntimeException;
use Throwable;

final class NodeRoleOperationException extends RuntimeException
{
    public readonly ?CommandResult $result;

    /** @mago-expect lint:excessive-parameter-list Stable operation failures expose each required field directly. */
    public function __construct(
        public readonly string $step,
        public readonly string $errorCode,
        public readonly string $underlyingErrorCode,
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

    /** @return array{message: string, step: string, errorCode: string, underlyingErrorCode: string} */
    public function __debugInfo(): array
    {
        return [
            'message' => $this->getMessage(),
            'step' => $this->step,
            'errorCode' => $this->errorCode,
            'underlyingErrorCode' => $this->underlyingErrorCode,
        ];
    }
}
