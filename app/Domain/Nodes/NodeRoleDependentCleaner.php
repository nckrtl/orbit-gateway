<?php

declare(strict_types=1);

namespace App\Domain\Nodes;

interface NodeRoleDependentCleaner
{
    public function clean(NodeRoleDependencySet $dependencies): void;
}
