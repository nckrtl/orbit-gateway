<?php

declare(strict_types=1);

namespace App\Domain\Nodes;

use App\Models\Node;
use App\Models\NodeRole;

interface RoleBaselineConverger
{
    public function converge(Node $node, NodeRole $assignment): void;

    /** @mago-expect lint:no-boolean-flag-parameter The role lifecycle contract carries the explicit purge-data choice. */
    public function remove(Node $node, NodeRole $assignment, bool $purgeData): void;
}
