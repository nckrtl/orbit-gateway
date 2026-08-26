<?php

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Actions\Nodes\CompleteMacOsAppDevSetupAction;
use App\Actions\Nodes\GenerateMacOsAppDevSetupScriptAction;
use App\Data\Nodes\NodeRoleResponseData;
use App\Http\Controllers\Controller;
use App\Http\Requests\Nodes\MacOsAppDevSetupResultRequest;
use App\Http\Requests\Nodes\MacOsAppDevSetupScriptRequest;
use App\Models\Node;
use Illuminate\Http\JsonResponse;

final class NodeRoleSetupsController extends Controller
{
    public function script(
        MacOsAppDevSetupScriptRequest $request,
        GenerateMacOsAppDevSetupScriptAction $action,
    ): JsonResponse {
        /** @var mixed $caller */
        $caller = $request->user();

        if (! $caller instanceof Node) {
            abort(403);
        }

        return response()->json([
            'data' => $action->execute($caller, $request->facts())->toArray(),
            'meta' => ['request_id' => $request->attributes->getString('orbit.request_id')],
        ]);
    }

    public function result(
        MacOsAppDevSetupResultRequest $request,
        CompleteMacOsAppDevSetupAction $action,
    ): JsonResponse {
        /** @var mixed $caller */
        $caller = $request->user();

        if (! $caller instanceof Node) {
            abort(403);
        }

        return response()->json([
            'data' => NodeRoleResponseData::fromModel($action->execute($caller, $request->result()))->toArray(),
            'meta' => ['request_id' => $request->attributes->getString('orbit.request_id')],
        ]);
    }
}
