<?php

declare(strict_types=1);

namespace App\Infrastructure\Processes;

final readonly class ProcessInvocation
{
    /** @param non-empty-list<string> $arguments */
    public function __construct(
        public array $arguments,
        public float $timeout = 900.0,
        public ?string $input = null,
        public ?ProtectedInput $protectedInput = null,
    ) {}
}
