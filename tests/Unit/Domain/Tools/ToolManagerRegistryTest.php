<?php

declare(strict_types=1);

use App\Domain\Tools\ToolManager;
use App\Domain\Tools\ToolManagerName;
use App\Domain\Tools\ToolManagerRegistry;
use App\Domain\Tools\ToolOperation;
use App\Domain\Tools\ToolRemovalPlan;
use App\Models\Node;
use Closure;

describe(ToolManagerRegistry::class, function (): void {
    it('indexes the closed manager set in constructor order and filters by node support', function (): void {
        $linuxAppNode = tool_manager_registry_node('linux');
        $apt = fake_tool_manager(ToolManagerName::Apt, static fn (): bool => true);
        $vp = fake_tool_manager(ToolManagerName::Vp, static fn (Node $node): bool => $node->platform === 'linux');
        $composer = fake_tool_manager(ToolManagerName::Composer, static fn (Node $node): bool => $node->platform === 'linux');
        $registry = new ToolManagerRegistry([$apt, $vp, $composer]);

        expect($registry->find('apt'))->toBe($apt)
            ->and($registry->find('vp'))->toBe($vp)
            ->and($registry->find('composer'))->toBe($composer)
            ->and($registry->find('npm'))->toBeNull()
            ->and(array_map(
                static fn (ToolManager $manager): string => $manager->name()->value,
                $registry->supportedFor($linuxAppNode),
            ))->toBe(['apt', 'vp', 'composer']);
    });
});

function fake_tool_manager(ToolManagerName $name, callable $supportsNode): ToolManager
{
    return new class($name, $supportsNode) implements ToolManager
    {
        public function __construct(
            private readonly ToolManagerName $name,
            private readonly Closure $supportsNode,
        ) {}

        public function name(): ToolManagerName
        {
            return $this->name;
        }

        public function supportsNode(Node $node): bool
        {
            return ($this->supportsNode)($node);
        }

        public function validatePackage(string $package): bool
        {
            return true;
        }

        public function managerVersion(Node $node): string
        {
            return '1.0.0';
        }

        public function candidateVersion(Node $node, string $package, ToolOperation $operation): ?string
        {
            return '1.0.0';
        }

        public function installedVersion(Node $node, string $package): ?string
        {
            return '1.0.0';
        }

        public function normalizeVersion(string $rawVersion): ?string
        {
            return $rawVersion;
        }

        public function install(Node $node, string $package): void {}

        public function update(Node $node, string $package): void {}

        public function planRemoval(Node $node, string $package): ToolRemovalPlan
        {
            return new ToolRemovalPlan([$package]);
        }

        public function remove(Node $node, string $package): void {}
    };
}

function tool_manager_registry_node(string $platform): Node
{
    return new Node([
        'name' => 'tool-node',
        'status' => 'active',
        'platform' => $platform,
        'public_ssh_host' => '127.0.0.1',
        'ssh_user' => 'orbit',
    ]);
}
