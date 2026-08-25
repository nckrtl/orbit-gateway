<?php

declare(strict_types=1);

namespace App\Data\Gateway;

use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\SnakeCaseMapper;

#[MapOutputName(SnakeCaseMapper::class)]
final class GatewayStatusData extends Data
{
    public function __construct(
        public string $name,
        public string $status,
        public string $version,
        public string $phpVersion,
        public string $laravelVersion,
    ) {}
}
