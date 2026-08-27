<?php

declare(strict_types=1);

namespace App\Domain\Tools;

use App\Models\Node;
use LogicException;

final class ToolManagerRegistry
{
    /** @var array<string, ToolManager> */
    private array $managers;

    /** @param non-empty-list<ToolManager> $managers */
    public function __construct(array $managers)
    {
        $indexed = [];

        foreach ($managers as $manager) {
            $name = $manager->name()->value;

            if (array_key_exists($name, $indexed)) {
                throw new LogicException("Duplicate tool manager [{$name}].");
            }

            $indexed[$name] = $manager;
        }

        $this->managers = $indexed;
    }

    public function find(string $name): ?ToolManager
    {
        return $this->managers[$name] ?? null;
    }

    /** @return list<ToolManager> */
    public function supportedFor(Node $node): array
    {
        return array_values(array_filter(
            $this->managers,
            static fn (ToolManager $manager): bool => $manager->supportsNode($node),
        ));
    }
}
