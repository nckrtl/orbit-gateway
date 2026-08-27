<?php

declare(strict_types=1);

namespace App\Domain\Nodes;

use RuntimeException;

final class NodeRoleValidationException extends RuntimeException
{
    /** @param array<string, mixed> $details */
    public function __construct(
        string $message,
        public readonly array $details = [],
    ) {
        parent::__construct($message);
    }
}
