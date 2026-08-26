<?php

declare(strict_types=1);

namespace App\Infrastructure\Firewall;

final readonly class UfwManagedRule
{
    /** @param non-empty-list<string> $arguments */
    public function __construct(
        public UfwRuleShape $shape,
        public array $arguments,
    ) {}
}
