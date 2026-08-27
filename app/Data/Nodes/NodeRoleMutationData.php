<?php

declare(strict_types=1);

namespace App\Data\Nodes;

use App\Domain\Nodes\RoleName;
use App\Models\Node;
use App\Models\NodeRole;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\SnakeCaseMapper;

#[MapOutputName(SnakeCaseMapper::class)]
final class NodeRoleMutationData extends Data
{
    public function __construct(
        public int $nodeId,
        public string $nodeName,
        public string $role,
        public ?NodeRoleAssignmentData $assignment,
        public bool $removed,
    ) {}

    public static function added(Node $node, NodeRole $assignment): self
    {
        return new self(
            nodeId: $node->id,
            nodeName: $node->name,
            role: $assignment->role->value,
            assignment: NodeRoleAssignmentData::fromModel($assignment),
            removed: false,
        );
    }

    public static function removed(Node $node, RoleName $role): self
    {
        return new self(
            nodeId: $node->id,
            nodeName: $node->name,
            role: $role->value,
            assignment: null,
            removed: true,
        );
    }
}
