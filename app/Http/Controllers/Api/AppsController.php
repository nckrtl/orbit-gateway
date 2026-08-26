<?php

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Actions\Apps\CreateAppAction;
use App\Actions\Apps\ListAppsAction;
use App\Actions\Apps\RemoveAppAction;
use App\Actions\Apps\ShowAppAction;
use App\Data\Apps\AppData;
use App\Http\Authorization\RequiresNodeAccess;
use App\Http\Authorization\ServingNode;
use App\Http\Controllers\Controller;
use App\Http\Requests\Apps\StoreAppRequest;
use App\Models\App as OrbitApp;
use App\Models\Node;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class AppsController extends Controller
{
    #[RequiresNodeAccess(ServingNode::Collection)]
    public function index(Request $request, ListAppsAction $action): JsonResponse
    {
        /** @mago-expect analysis:mixed-assignment The authenticated peer resolver returns a Node. */
        $consumer = $request->user();
        assert($consumer instanceof Node, description: 'Authenticated peer must be a Node.');

        return response()->json([
            'data' => $action
                ->handle($consumer)
                ->map(static fn (OrbitApp $app): array => AppData::fromModel($app)->toArray())
                ->values()
                ->all(),
            'meta' => $this->meta($request),
        ]);
    }

    #[RequiresNodeAccess(ServingNode::Gateway)]
    public function store(StoreAppRequest $request, CreateAppAction $action): JsonResponse
    {
        $result = $action->execute($request->payload());

        return response()->json(
            [
                'data' => AppData::fromModel($result['app'])->toArray(),
                'meta' => $this->meta($request),
            ],
            $result['created'] ? 201 : 200,
        );
    }

    #[RequiresNodeAccess(ServingNode::AppOwning)]
    public function show(Request $request, OrbitApp $app, ShowAppAction $action): JsonResponse
    {
        return response()->json([
            'data' => AppData::fromModel($action->handle($app))->toArray(),
            'meta' => $this->meta($request),
        ]);
    }

    #[RequiresNodeAccess(ServingNode::AppOwning)]
    public function destroy(Request $request, OrbitApp $app, RemoveAppAction $action): JsonResponse
    {
        return response()->json([
            'data' => AppData::fromModel($action->execute($app))->toArray(),
            'meta' => $this->meta($request),
        ]);
    }

    /** @return array{request_id: string} */
    private function meta(Request $request): array
    {
        return ['request_id' => $request->attributes->getString('orbit.request_id')];
    }
}
