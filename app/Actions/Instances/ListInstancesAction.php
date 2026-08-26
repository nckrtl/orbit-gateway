<?php

declare(strict_types=1);

namespace App\Actions\Instances;

use App\Domain\Nodes\NodeAccessAuthorizer;
use App\Models\Instance;
use App\Models\Node;
use Illuminate\Database\Eloquent\Collection;

final readonly class ListInstancesAction
{
    public function __construct(
        private NodeAccessAuthorizer $access,
    ) {}

    /** @return Collection<int, Instance> */
    public function handle(Node $consumer): Collection
    {
        return Instance::query()
            ->when(
                ! $this->access->hasGatewayAuthority($consumer),
                fn ($query) => $query->whereIn(
                    'node_id',
                    $this->access->accessibleNodeIds($consumer),
                ),
            )
            ->latest('id')
            ->get();
    }
}
