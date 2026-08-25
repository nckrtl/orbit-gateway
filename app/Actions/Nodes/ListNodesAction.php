<?php

declare(strict_types=1);

namespace App\Actions\Nodes;

use App\Models\Node;
use Illuminate\Database\Eloquent\Collection;

final readonly class ListNodesAction
{
    /** @return Collection<int, Node> */
    public function handle(): Collection
    {
        return Node::query()
            ->with('roles')
            ->orderBy('name')
            ->orderBy('id')
            ->get();
    }
}
