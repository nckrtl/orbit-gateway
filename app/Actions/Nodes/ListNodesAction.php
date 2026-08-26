<?php

declare(strict_types=1);

namespace App\Actions\Nodes;

use App\Domain\Nodes\NodeAccessAuthorizer;
use App\Models\Node;
use Illuminate\Database\Eloquent\Collection;

final readonly class ListNodesAction
{
    public function __construct(
        private NodeAccessAuthorizer $access,
    ) {}

    /** @return Collection<int, Node> */
    public function handle(Node $consumer): Collection
    {
        return Node::query()
            ->with('roles')
            ->when(
                ! $this->access->hasGatewayAuthority($consumer),
                fn ($query) => $query->whereIn('id', $this->access->accessibleNodeIds($consumer)),
            )
            ->orderBy('name')
            ->orderBy('id')
            ->get();
    }
}
