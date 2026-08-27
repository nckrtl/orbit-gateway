<?php

declare(strict_types=1);

namespace App\Domain\Nodes;

final readonly class NodeRoleDependencySet
{
    /**
     * @param list<int> $instanceIds
     * @param list<int> $workspaceIds
     * @param list<int> $processIds
     * @param list<string> $summaries
     */
    public function __construct(
        public array $instanceIds,
        public array $workspaceIds,
        public array $processIds,
        public array $summaries,
    ) {}
}
