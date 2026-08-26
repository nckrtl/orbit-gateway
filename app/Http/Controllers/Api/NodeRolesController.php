<?php

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Actions\Nodes\AddNodeRoleAction;
use App\Data\Nodes\NodeRoleResponseData;
use App\Http\Controllers\Controller;
use App\Http\Requests\Nodes\AddNodeRoleRequest;
use App\Models\Node;
use Illuminate\Http\JsonResponse;

final class NodeRolesController extends Controller
{
    public function store(AddNodeRoleRequest $request, Node $node, AddNodeRoleAction $action): JsonResponse
    {
        $assignment = $action->execute($node, $request->role());

        return response()->json([
            'data' => NodeRoleResponseData::fromModel($assignment)->toArray(),
            'meta' => ['request_id' => $request->attributes->getString('orbit.request_id')],
        ]);
    }
}
