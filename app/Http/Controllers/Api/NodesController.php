<?php

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Actions\Nodes\ProvisionNodeAction;
use App\Data\Nodes\NodeData;
use App\Http\Controllers\Controller;
use App\Http\Requests\Nodes\ProvisionNodeRequest;
use Illuminate\Http\JsonResponse;

final class NodesController extends Controller
{
    /** @mago-expect analysis:mixed-assignment Request attributes are an untyped boundary. */
    public function store(ProvisionNodeRequest $request, ProvisionNodeAction $action): JsonResponse
    {
        $node = $action->execute($request->payload());
        $requestId = $request->attributes->get('orbit.request_id');

        return response()->json([
            'data' => NodeData::fromModel($node)->toArray(),
            'meta' => ['request_id' => is_string($requestId) ? $requestId : null],
        ], 201);
    }
}
