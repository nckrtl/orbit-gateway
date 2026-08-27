<?php

declare(strict_types=1);

namespace App\Domain\Tools;

use App\Models\Node;

interface ToolManager
{
    public function name(): ToolManagerName;

    public function supportsNode(Node $node): bool;

    public function validatePackage(string $package): bool;

    public function managerVersion(Node $node): string;

    public function candidateVersion(Node $node, string $package, ToolOperation $operation): ?string;

    public function installedVersion(Node $node, string $package): ?string;

    public function normalizeVersion(string $rawVersion): ?string;

    public function install(Node $node, string $package): void;

    public function update(Node $node, string $package): void;

    public function planRemoval(Node $node, string $package): ToolRemovalPlan;

    public function remove(Node $node, string $package): void;
}
