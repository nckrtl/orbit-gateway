<?php

declare(strict_types=1);

namespace App\Domain\Tools;

use Closure;

interface ToolOperationLock
{
    public function run(
        int $nodeId,
        ToolManagerName $manager,
        string $package,
        ToolOperation $operation,
        ?string $versionConstraint,
        Closure $callback,
    ): mixed;
}
