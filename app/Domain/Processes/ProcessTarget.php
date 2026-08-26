<?php

declare(strict_types=1);

namespace App\Domain\Processes;

use App\Models\Node;

final readonly class ProcessTarget
{
    public function __construct(
        public Node $node,
        public string $user,
        public string $checkoutPath,
    ) {}
}
