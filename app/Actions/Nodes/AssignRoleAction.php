<?php

declare(strict_types=1);

namespace App\Actions\Nodes;

use App\Domain\Nodes\RoleAssignmentException;
use App\Domain\Nodes\RoleName;
use App\Domain\Nodes\RoleRegistry;
use App\Models\Node;
use App\Models\NodeRole;
use Illuminate\Support\Facades\DB;

final readonly class AssignRoleAction
{
    public function __construct(
        private RoleRegistry $registry,
    ) {}

    /** @mago-expect lint:inline-variable-return The variable preserves the transaction result type. */
    public function execute(Node $node, RoleName $role): NodeRole
    {
        /** @var NodeRole $assignment */
        $assignment = DB::transaction(function () use ($node, $role): NodeRole {
            $existing = $node->roles()->where('role', $role->value)->first();

            if ($existing instanceof NodeRole) {
                return $existing;
            }

            $definition = $this->registry->definition($role);

            if ($definition->singleton) {
                $assigned = NodeRole::query()
                    ->with('node')
                    ->where('role', $role->value)
                    ->first();

                if ($assigned instanceof NodeRole) {
                    throw new RoleAssignmentException(
                        "Role [{$role->value}] is already assigned to node [{$assigned->node->name}].",
                    );
                }
            }

            foreach ($node->roles()->get() as $assigned) {
                if ($this->registry->conflicts($role, $assigned->role)) {
                    throw new RoleAssignmentException(
                        "Role [{$role->value}] conflicts with assigned role [{$assigned->role->value}].",
                    );
                }
            }

            return $node->roles()->create(['role' => $role]);
        });

        return $assignment;
    }
}
