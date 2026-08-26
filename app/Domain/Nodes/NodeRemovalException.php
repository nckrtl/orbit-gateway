<?php

declare(strict_types=1);

namespace App\Domain\Nodes;

use App\Infrastructure\Processes\CommandResult;
use RuntimeException;
use Throwable;

final class NodeRemovalException extends RuntimeException
{
    public function __construct(
        public readonly string $step,
        public readonly string $errorCode,
        string $message,
        public readonly ?CommandResult $result = null,
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, previous: $previous);
    }
}
