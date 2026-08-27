<?php

declare(strict_types=1);

namespace App\Domain\Tools;

use RuntimeException;

final class ToolOperationException extends RuntimeException
{
    /** @mago-expect lint:excessive-parameter-list Stable operation failures expose each required field directly. */
    public function __construct(
        public readonly string $step,
        public readonly string $errorCode,
        public readonly ToolOutcome $outcome,
        public readonly int $status,
        public readonly int $nodeId,
        public readonly string $manager,
        public readonly string $package,
        public readonly ?string $versionConstraint,
        string $message,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, previous: $previous);
    }
}
