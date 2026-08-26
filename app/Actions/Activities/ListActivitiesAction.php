<?php

declare(strict_types=1);

namespace App\Actions\Activities;

use App\Models\Activity;
use Illuminate\Database\Eloquent\Collection;

final readonly class ListActivitiesAction
{
    /** @return Collection<int, Activity> */
    public function handle(int $limit, string $excludeRequestId, ?string $requestId = null): Collection
    {
        return Activity::query()
            ->when(
                $excludeRequestId !== '',
                static fn ($query) => $query->where('request_id', '!=', $excludeRequestId),
            )
            ->when(
                $requestId !== null,
                static fn ($query) => $query->where('request_id', $requestId),
            )
            ->latest('id')
            ->limit($limit)
            ->get();
    }
}
