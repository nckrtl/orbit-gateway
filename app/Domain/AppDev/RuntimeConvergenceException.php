<?php

declare(strict_types=1);

namespace App\Domain\AppDev;

use App\Infrastructure\Processes\CommandResult;
use RuntimeException;
use Throwable;

final class RuntimeConvergenceException extends RuntimeException
{
    public function __construct(
        public readonly string $step,
        public readonly string $errorCode,
        string $message,
        ?Throwable $previous = null,
        public readonly ?CommandResult $result = null,
    ) {
        parent::__construct($message, previous: $previous);
    }
}
