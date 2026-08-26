<?php

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Actions\Nodes\AddNodeAccessAction;
use App\Actions\Nodes\RemoveNodeAccessAction;
use App\Http\Authorization\RequiresNodeAccess;
use App\Http\Authorization\ServingNode;
use App\Http\Controllers\Controller;
use App\Models\Node;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

#[RequiresNodeAccess(ServingNode::Gateway)]
final class NodeAccessController extends Controller
{
    public function store(
        Request $request,
        Node $servingNode,
        Node $consumerNode,
        AddNodeAccessAction $action,
    ): JsonResponse {
        return response()->json([
            'data' => $action->execute($consumerNode, $servingNode)->toArray(),
            'meta' => $this->meta($request),
        ]);
    }

    public function destroy(
        Request $request,
        Node $servingNode,
        Node $consumerNode,
        RemoveNodeAccessAction $action,
    ): JsonResponse {
        /** @mago-expect analysis:mixed-assignment The authenticated peer resolver returns a Node. */
        $caller = $request->user();
        assert($caller instanceof Node, description: 'Authenticated peer must be a Node.');

        return response()->json([
            'data' => $action->execute($consumerNode, $servingNode, $caller)->toArray(),
            'meta' => $this->meta($request),
        ]);
    }

    /** @return array{request_id: string} */
    private function meta(Request $request): array
    {
        return ['request_id' => $request->attributes->getString('orbit.request_id')];
    }
}
