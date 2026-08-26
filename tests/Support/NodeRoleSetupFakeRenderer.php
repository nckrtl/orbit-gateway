<?php

declare(strict_types=1);

namespace Tests\Support;

use App\Data\Nodes\MacOsAppDevSetupFactsData;
use App\Domain\MacOs\MacOsAppDevSetupPlan;
use App\Domain\MacOs\MacOsAppDevSetupRenderer;
use App\Models\Node;
use App\Models\NodeRole;

final class NodeRoleSetupFakeRenderer implements MacOsAppDevSetupRenderer
{
    public int $calls = 0;

    public function render(
        Node $node,
        NodeRole $assignment,
        MacOsAppDevSetupFactsData $facts,
    ): MacOsAppDevSetupPlan {
        $this->calls++;

        return new MacOsAppDevSetupPlan(
            summary: 'Install the approved local app-dev dependencies.',
            script: "#!/bin/bash\nexit 0\n",
        );
    }
}
