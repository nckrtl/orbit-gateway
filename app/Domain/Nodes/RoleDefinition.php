<?php

declare(strict_types=1);

namespace App\Domain\Nodes;

final readonly class RoleDefinition
{
    /** @param list<RoleName> $conflicts */
    public function __construct(
        public RoleName $name,
        public bool $singleton,
        public array $conflicts = [],
    ) {}
}
