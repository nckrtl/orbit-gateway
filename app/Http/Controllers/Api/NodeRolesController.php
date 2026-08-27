<?php

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Actions\Nodes\AddNodeRoleAction;
use App\Actions\Nodes\ListNodeRolesAction;
use App\Actions\Nodes\RemoveNodeRoleAction;
use App\Data\Nodes\NodeRoleAssignmentData;
use App\Data\Nodes\NodeRoleMutationData;
use App\Domain\Nodes\NodeRoleValidationException;
use App\Domain\Nodes\RoleAssignmentException;
use App\Domain\Nodes\RoleName;
use App\Domain\Nodes\RoleRegistry;
use App\Http\Authorization\RequiresNodeAccess;
use App\Http\Authorization\ServingNode;
use App\Http\Controllers\Controller;
use App\Http\Requests\Nodes\AddNodeRoleRequest;
use App\Http\Requests\Nodes\RemoveNodeRoleRequest;
use App\Models\Node;
use App\Models\NodeRole;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

#[RequiresNodeAccess(ServingNode::Target)]
final class NodeRolesController extends Controller
{
    public function index(Request $request, Node $node, ListNodeRolesAction $action): JsonResponse
    {
        return response()->json([
            'data' => $action
                ->execute($node)
                ->map(
                    static fn (NodeRole $assignment): array => NodeRoleAssignmentData::fromModel(
                        $assignment,
                    )->toArray(),
                )
                ->values()
                ->all(),
            'meta' => $this->meta($request),
        ]);
    }

    public function store(
        AddNodeRoleRequest $request,
        Node $node,
        AddNodeRoleAction $action,
        RoleRegistry $registry,
    ): JsonResponse {
        $role = $request->role();
        $this->guardMutable($role, $registry);

        try {
            $result = $action->execute($node, $role, $request->convergeExisting());
        } catch (RoleAssignmentException $exception) {
            throw new NodeRoleValidationException(
                message: $exception->getMessage(),
                details: ['field' => 'role', 'role' => $role->value],
            );
        }

        return response()->json(
            [
                'data' => NodeRoleMutationData::added($node, $result['assignment'])->toArray(),
                'meta' => $this->meta($request),
            ],
            $result['created'] ? 201 : 200,
        );
    }

    public function destroy(
        RemoveNodeRoleRequest $request,
        Node $node,
        RemoveNodeRoleAction $action,
        RoleRegistry $registry,
    ): JsonResponse {
        $validatedRole = $request->role();
        $this->guardMutable($validatedRole, $registry);
        try {
            $action->execute(
                $node,
                $validatedRole,
                $request->force(),
                $request->purgeData(),
            );
        } catch (NodeRoleValidationException $exception) {
            if ($exception->details !== []) {
                throw $exception;
            }

            throw new NodeRoleValidationException(
                message: $exception->getMessage(),
                details: ['field' => 'role', 'role' => $validatedRole->value],
            );
        }

        return response()->json([
            'data' => NodeRoleMutationData::removed($node, $validatedRole)->toArray(),
            'meta' => $this->meta($request),
        ]);
    }

    private function guardMutable(RoleName $role, RoleRegistry $registry): void
    {
        if ($registry->definition($role)->mutable) {
            return;
        }

        throw new NodeRoleValidationException(
            message: "Role [{$role->value}] is protected from generic mutation.",
            details: ['field' => 'role', 'role' => $role->value],
        );
    }

    /** @return array{request_id: string} */
    private function meta(Request $request): array
    {
        return ['request_id' => $request->attributes->getString('orbit.request_id')];
    }
}
