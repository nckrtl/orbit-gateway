<?php

declare(strict_types=1);

namespace App\Infrastructure\Ssh;

use App\Infrastructure\Processes\CommandResult;
use RuntimeException;
use Throwable;

final class SshHostKeyScanException extends RuntimeException
{
    public function __construct(
        string $message,
        public readonly ?CommandResult $result = null,
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, previous: $previous);
    }
}
