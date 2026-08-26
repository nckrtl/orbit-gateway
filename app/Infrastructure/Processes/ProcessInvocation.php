<?php

declare(strict_types=1);

namespace App\Infrastructure\Processes;

use SensitiveParameter;

final readonly class ProcessInvocation
{
    /** @param non-empty-list<string> $arguments */
    public function __construct(
        public array $arguments,
        public float $timeout = 900.0,
        #[SensitiveParameter]
        public ?string $input = null,
        #[SensitiveParameter]
        public ?ProtectedInput $protectedInput = null,
    ) {}
}
