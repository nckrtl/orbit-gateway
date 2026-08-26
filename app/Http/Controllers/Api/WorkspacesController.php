<?php

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Actions\Workspaces\CreateWorkspaceAction;
use App\Actions\Workspaces\ListWorkspacesAction;
use App\Actions\Workspaces\RemoveWorkspaceAction;
use App\Actions\Workspaces\ShowWorkspaceAction;
use App\Actions\Workspaces\UpdateWorkspacePhpAction;
use App\Data\Workspaces\WorkspaceData;
use App\Http\Authorization\RequiresNodeAccess;
use App\Http\Authorization\ServingNode;
use App\Http\Controllers\Controller;
use App\Http\Requests\Workspaces\StoreWorkspaceRequest;
use App\Http\Requests\Workspaces\UpdateWorkspacePhpRequest;
use App\Models\Workspace;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class WorkspacesController extends Controller
{
    #[RequiresNodeAccess(ServingNode::Collection)]
    public function index(Request $request, ListWorkspacesAction $action): JsonResponse
    {
        return response()->json([
            'data' => $action
                ->handle()
                ->map(static fn (Workspace $workspace): array => WorkspaceData::fromModel($workspace)->toArray())
                ->values()
                ->all(),
            'meta' => $this->meta($request),
        ]);
    }

    #[RequiresNodeAccess(ServingNode::WorkspaceOwning)]
    public function store(StoreWorkspaceRequest $request, CreateWorkspaceAction $action): JsonResponse
    {
        $result = $action->execute($request->payload());

        return response()->json(
            [
                'data' => WorkspaceData::fromModel($result['workspace'])->toArray(),
                'meta' => $this->meta($request),
            ],
            $result['created'] ? 201 : 200,
        );
    }

    #[RequiresNodeAccess(ServingNode::WorkspaceOwning)]
    public function show(Request $request, Workspace $workspace, ShowWorkspaceAction $action): JsonResponse
    {
        return response()->json([
            'data' => WorkspaceData::fromModel($action->handle($workspace))->toArray(),
            'meta' => $this->meta($request),
        ]);
    }

    #[RequiresNodeAccess(ServingNode::WorkspaceOwning)]
    public function destroy(Request $request, Workspace $workspace, RemoveWorkspaceAction $action): JsonResponse
    {
        return response()->json([
            'data' => WorkspaceData::fromModel($action->execute($workspace))->toArray(),
            'meta' => $this->meta($request),
        ]);
    }

    #[RequiresNodeAccess(ServingNode::WorkspaceOwning)]
    public function php(
        UpdateWorkspacePhpRequest $request,
        Workspace $workspace,
        UpdateWorkspacePhpAction $action,
    ): JsonResponse {
        return response()->json([
            'data' => WorkspaceData::fromModel($action->execute($workspace, $request->phpVersion()))->toArray(),
            'meta' => $this->meta($request),
        ]);
    }

    /** @return array{request_id: string} */
    private function meta(Request $request): array
    {
        return ['request_id' => $request->attributes->getString('orbit.request_id')];
    }
}
