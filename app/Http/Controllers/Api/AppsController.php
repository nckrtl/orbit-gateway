<?php

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Actions\Apps\CreateAppAction;
use App\Actions\Apps\ListAppsAction;
use App\Actions\Apps\RemoveAppAction;
use App\Actions\Apps\ShowAppAction;
use App\Data\Apps\AppData;
use App\Http\Controllers\Controller;
use App\Http\Requests\Apps\StoreAppRequest;
use App\Models\App as OrbitApp;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class AppsController extends Controller
{
    public function index(Request $request, ListAppsAction $action): JsonResponse
    {
        return response()->json([
            'data' => $action
                ->handle()
                ->map(static fn (OrbitApp $app): array => AppData::fromModel($app)->toArray())
                ->values()
                ->all(),
            'meta' => $this->meta($request),
        ]);
    }

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

    public function show(Request $request, OrbitApp $app, ShowAppAction $action): JsonResponse
    {
        return response()->json([
            'data' => AppData::fromModel($action->handle($app))->toArray(),
            'meta' => $this->meta($request),
        ]);
    }

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
