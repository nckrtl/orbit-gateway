<?php

declare(strict_types=1);

namespace App\Data\Apps;

final readonly class CreateAppData
{
    /** @param array<array-key, mixed>|null $defaults */
    public function __construct(
        public string $name,
        public string $slug,
        public string $repositoryUrl,
        public ?array $defaults,
    ) {}
}
