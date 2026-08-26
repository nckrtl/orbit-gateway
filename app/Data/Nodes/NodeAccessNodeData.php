<?php

declare(strict_types=1);

namespace App\Data\Nodes;

use App\Models\Node;
use Spatie\LaravelData\Data;

final class NodeAccessNodeData extends Data
{
    public function __construct(
        public int $id,
        public string $name,
    ) {}

    public static function fromModel(Node $node): self
    {
        return new self(id: $node->id, name: $node->name);
    }
}
