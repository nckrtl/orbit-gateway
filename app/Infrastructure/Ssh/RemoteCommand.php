<?php

declare(strict_types=1);

namespace App\Infrastructure\Ssh;

use App\Infrastructure\Processes\ProtectedInput;
use InvalidArgumentException;

final readonly class RemoteCommand
{
    /** @param non-empty-list<string> $arguments */
    public function __construct(
        public array $arguments,
        public ?string $input = null,
        public ?ProtectedInput $protectedInput = null,
    ) {
        if ($arguments === []) {
            throw new InvalidArgumentException('A remote command needs at least one argument.');
        }
    }

    public function shellCommand(): string
    {
        return implode(' ', array_map(escapeshellarg(...), $this->arguments));
    }
}
