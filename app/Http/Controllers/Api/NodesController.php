<?php

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Actions\Nodes\ListNodesAction;
use App\Actions\Nodes\ProvisionNodeAction;
use App\Actions\Nodes\RemoveNodeAction;
use App\Actions\Nodes\ShowNodeAction;
use App\Data\Nodes\NodeAccessData;
use App\Data\Nodes\NodeData;
use App\Http\Authorization\RequiresNodeAccess;
use App\Http\Authorization\ServingNode;
use App\Http\Controllers\Controller;
use App\Http\Requests\Nodes\ProvisionNodeRequest;
use App\Models\Node;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class NodesController extends Controller
{
    #[RequiresNodeAccess(ServingNode::Collection)]
    public function index(Request $request, ListNodesAction $action): JsonResponse
    {
        /** @mago-expect analysis:mixed-assignment The authenticated peer resolver returns a Node. */
        $consumer = $request->user();
        assert($consumer instanceof Node, description: 'Authenticated peer must be a Node.');

        $nodes = $action->handle($consumer);

        return response()->json([
            'data' => $nodes
                ->map(static fn (Node $node): array => NodeData::fromModel($node)->toArray())
                ->values()
                ->all(),
            'meta' => ['request_id' => $request->attributes->getString('orbit.request_id')],
        ]);
    }

    #[RequiresNodeAccess(ServingNode::Target)]
    public function show(Request $request, Node $node, ShowNodeAction $action): JsonResponse
    {
        $node = $action->handle($node);

        return response()->json([
            'data' => [
                ...NodeData::fromModel($node)->toArray(),
                'access' => NodeAccessData::fromModel($node)->toArray(),
            ],
            'meta' => ['request_id' => $request->attributes->getString('orbit.request_id')],
        ]);
    }

    /** @mago-expect analysis:mixed-assignment The authenticated peer resolver returns a Node. */
    #[RequiresNodeAccess(ServingNode::Target)]
    public function destroy(Request $request, Node $node, RemoveNodeAction $action): JsonResponse
    {
        $caller = $request->user();

        if (! $caller instanceof Node) {
            abort(403);
        }

        $request->attributes->set('orbit.target_node_snapshot', [
            'id' => $node->id,
            'name' => $node->name,
        ]);

        return response()->json([
            'data' => $action->execute($node, $caller)->toArray(),
            'meta' => ['request_id' => $request->attributes->getString('orbit.request_id')],
        ]);
    }

    /** @mago-expect analysis:mixed-assignment Request attributes are an untyped boundary. */
    #[RequiresNodeAccess(ServingNode::Gateway)]
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
