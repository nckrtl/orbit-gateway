<?php

declare(strict_types=1);

namespace App\Domain\Nodes;

use App\Models\Node;

interface NodeConverger
{
    public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void;
}
