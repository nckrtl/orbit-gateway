<?php

declare(strict_types=1);

namespace App\Actions\Nodes;

use App\Domain\Nodes\RoleName;
use App\Models\Node;
use App\Models\NodeRole;
use Illuminate\Database\Eloquent\Collection;

final readonly class ListNodeRolesAction
{
    /** @return Collection<int, NodeRole> */
    public function execute(Node $node): Collection
    {
        $order = array_flip(array_map(
            static fn (RoleName $role): string => $role->value,
            RoleName::cases(),
        ));

        return $node
            ->roles()
            ->get()
            ->sort(static function (NodeRole $first, NodeRole $second) use ($order): int {
                $roleOrder = $order[$first->role->value] <=> $order[$second->role->value];

                return $roleOrder !== 0 ? $roleOrder : $first->id <=> $second->id;
            })
            ->values();
    }
}
