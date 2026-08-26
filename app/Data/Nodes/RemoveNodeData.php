<?php

declare(strict_types=1);

namespace App\Data\Nodes;

use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\SnakeCaseMapper;

#[MapOutputName(SnakeCaseMapper::class)]
final class RemoveNodeData extends Data
{
    public function __construct(
        public int $id,
        public string $name,
        public bool $removed,
        public bool $wireguardPeerRemoved,
        public bool $dnsRecordsRemoved,
    ) {}
}
