<?php

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Actions\Instances\CreateInstanceAction;
use App\Actions\Instances\ListInstancesAction;
use App\Actions\Instances\RemoveInstanceAction;
use App\Actions\Instances\ShowInstanceAction;
use App\Actions\Instances\UpdateInstancePhpAction;
use App\Data\Instances\InstanceData;
use App\Http\Controllers\Controller;
use App\Http\Requests\Instances\StoreInstanceRequest;
use App\Http\Requests\Instances\UpdateInstancePhpRequest;
use App\Models\Instance;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class InstancesController extends Controller
{
    public function index(Request $request, ListInstancesAction $action): JsonResponse
    {
        return response()->json([
            'data' => $action
                ->handle()
                ->map(static fn (Instance $instance): array => InstanceData::fromModel($instance)->toArray())
                ->values()
                ->all(),
            'meta' => $this->meta($request),
        ]);
    }

    public function store(StoreInstanceRequest $request, CreateInstanceAction $action): JsonResponse
    {
        $result = $action->execute($request->payload());

        return response()->json(
            [
                'data' => InstanceData::fromModel($result['instance'])->toArray(),
                'meta' => $this->meta($request),
            ],
            $result['created'] ? 201 : 200,
        );
    }

    public function show(Request $request, Instance $instance, ShowInstanceAction $action): JsonResponse
    {
        return response()->json([
            'data' => InstanceData::fromModel($action->handle($instance))->toArray(),
            'meta' => $this->meta($request),
        ]);
    }

    public function destroy(Request $request, Instance $instance, RemoveInstanceAction $action): JsonResponse
    {
        return response()->json([
            'data' => InstanceData::fromModel($action->execute($instance))->toArray(),
            'meta' => $this->meta($request),
        ]);
    }

    public function php(
        UpdateInstancePhpRequest $request,
        Instance $instance,
        UpdateInstancePhpAction $action,
    ): JsonResponse {
        return response()->json([
            'data' => InstanceData::fromModel($action->execute($instance, $request->phpVersion()))->toArray(),
            'meta' => $this->meta($request),
        ]);
    }

    /** @return array{request_id: string} */
    private function meta(Request $request): array
    {
        return ['request_id' => $request->attributes->getString('orbit.request_id')];
    }
}
