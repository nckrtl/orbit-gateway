<?php

declare(strict_types=1);

namespace App\Domain\MacOs;

use App\Data\Nodes\MacOsAppDevSetupFactsData;
use App\Models\Node;
use App\Models\NodeRole;

interface MacOsAppDevSetupRenderer
{
    public function render(Node $node, NodeRole $assignment, MacOsAppDevSetupFactsData $facts): MacOsAppDevSetupPlan;
}
