<?php

declare(strict_types=1);

namespace App\Actions\Workspaces;

use App\Domain\Nodes\NodeAccessAuthorizer;
use App\Models\Node;
use App\Models\Workspace;
use Illuminate\Database\Eloquent\Collection;

final readonly class ListWorkspacesAction
{
    public function __construct(
        private NodeAccessAuthorizer $access,
    ) {}

    /** @return Collection<int, Workspace> */
    public function handle(Node $consumer): Collection
    {
        return Workspace::query()
            ->with('instance')
            ->when(
                ! $this->access->hasGatewayAuthority($consumer),
                fn ($query) => $query->whereHas(
                    'instance',
                    fn ($instance) => $instance->whereIn(
                        'node_id',
                        $this->access->accessibleNodeIds($consumer),
                    ),
                ),
            )
            ->latest('id')
            ->get();
    }
}
