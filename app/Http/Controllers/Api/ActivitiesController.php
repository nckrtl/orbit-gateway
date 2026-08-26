<?php

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Actions\Activities\ListActivitiesAction;
use App\Actions\Activities\ShowActivityAction;
use App\Data\Activities\ActivityData;
use App\Http\Authorization\RequiresNodeAccess;
use App\Http\Authorization\ServingNode;
use App\Http\Controllers\Controller;
use App\Http\Requests\Activities\ListActivitiesRequest;
use App\Models\Activity;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

#[RequiresNodeAccess(ServingNode::Gateway)]
final class ActivitiesController extends Controller
{
    public function index(ListActivitiesRequest $request, ListActivitiesAction $action): JsonResponse
    {
        $requestId = $request->attributes->getString('orbit.request_id');
        $activities = $action->handle($request->limit(), $requestId, $request->requestId());

        return response()->json([
            'data' => $activities
                ->map(static fn (Activity $activity): array => ActivityData::fromModel($activity)->toArray())
                ->values()
                ->all(),
            'meta' => [
                'limit' => $request->limit(),
                'count' => $activities->count(),
                'request_id' => $requestId,
            ],
        ]);
    }

    public function show(Request $request, Activity $activity, ShowActivityAction $action): JsonResponse
    {
        return response()->json([
            'data' => ActivityData::fromModel($action->handle($activity))->toArray(),
            'meta' => ['request_id' => $request->attributes->getString('orbit.request_id')],
        ]);
    }
}
