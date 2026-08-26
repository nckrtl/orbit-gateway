<?php

declare(strict_types=1);

namespace App\Actions\Apps;

use App\Domain\Nodes\NodeAccessAuthorizer;
use App\Models\App as OrbitApp;
use App\Models\Node;
use Illuminate\Database\Eloquent\Collection;

final readonly class ListAppsAction
{
    public function __construct(
        private NodeAccessAuthorizer $access,
    ) {}

    /** @return Collection<int, OrbitApp> */
    public function handle(Node $consumer): Collection
    {
        return OrbitApp::query()
            ->when(
                ! $this->access->hasGatewayAuthority($consumer),
                fn ($query) => $query->whereHas(
                    'instances',
                    fn ($instances) => $instances->whereIn(
                        'node_id',
                        $this->access->accessibleNodeIds($consumer),
                    ),
                ),
            )
            ->latest('id')
            ->get();
    }
}
