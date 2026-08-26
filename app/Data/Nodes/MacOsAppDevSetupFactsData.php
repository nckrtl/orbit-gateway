<?php

declare(strict_types=1);

namespace App\Data\Nodes;

use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\SnakeCaseMapper;

#[MapOutputName(SnakeCaseMapper::class)]
final class MacOsAppDevSetupFactsData extends Data
{
    public function __construct(
        public string $platform,
        public string $architecture,
        public string $username,
        public string $homeDirectory,
    ) {}
}
