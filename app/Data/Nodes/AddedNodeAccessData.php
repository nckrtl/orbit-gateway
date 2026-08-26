<?php

declare(strict_types=1);

namespace App\Data\Nodes;

use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\SnakeCaseMapper;

#[MapOutputName(SnakeCaseMapper::class)]
final class AddedNodeAccessData extends Data
{
    public function __construct(
        public NodeAccessNodeData $consumerNode,
        public NodeAccessNodeData $servingNode,
        public bool $alreadyExists,
    ) {}
}
