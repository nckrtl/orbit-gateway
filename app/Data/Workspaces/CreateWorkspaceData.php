<?php

declare(strict_types=1);

namespace App\Data\Workspaces;

final readonly class CreateWorkspaceData
{
    public function __construct(
        public int $instanceId,
        public string $name,
        public string $branch,
        public ?string $checkoutPath,
        public ?string $phpVersion,
    ) {}
}
