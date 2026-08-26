<?php

declare(strict_types=1);

namespace App\Data\Nodes;

use App\Models\NodeRole;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\SnakeCaseMapper;

#[MapOutputName(SnakeCaseMapper::class)]
final class NodeRoleResponseData extends Data
{
    public function __construct(
        public int $nodeId,
        public string $nodeName,
        public NodeRoleAssignmentData $assignment,
    ) {}

    public static function fromModel(NodeRole $assignment): self
    {
        $assignment->loadMissing('node');

        return new self(
            nodeId: $assignment->node_id,
            nodeName: $assignment->node->name,
            assignment: NodeRoleAssignmentData::fromModel($assignment),
        );
    }
}
