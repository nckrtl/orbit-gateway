<?php

declare(strict_types=1);

namespace App\Data\Nodes;

use App\Models\Node;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\SnakeCaseMapper;

#[MapOutputName(SnakeCaseMapper::class)]
final class NodeAccessData extends Data
{
    /**
     * @param list<NodeAccessNodeData> $canAccess
     * @param list<NodeAccessNodeData> $accessibleBy
     */
    public function __construct(
        public array $canAccess,
        public array $accessibleBy,
    ) {}

    public static function fromModel(Node $node): self
    {
        /** @var list<NodeAccessNodeData> $canAccess */
        $canAccess = $node
            ->accessibleNodes
            ->map(NodeAccessNodeData::fromModel(...))
            ->values()
            ->all();
        /** @var list<NodeAccessNodeData> $accessibleBy */
        $accessibleBy = $node
            ->accessingNodes
            ->map(NodeAccessNodeData::fromModel(...))
            ->values()
            ->all();

        return new self(
            canAccess: $canAccess,
            accessibleBy: $accessibleBy,
        );
    }
}
