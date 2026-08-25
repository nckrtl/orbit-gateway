<?php

declare(strict_types=1);

namespace App\Infrastructure\Processes;

final readonly class CommandResult
{
    public function __construct(
        public int $exitCode,
        public string $stdout,
        public string $stderr,
        public int $durationMs,
        public bool $truncated,
    ) {}

    public function succeeded(): bool
    {
        return $this->exitCode === 0;
    }
}
