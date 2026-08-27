<?php

declare(strict_types=1);

namespace App\Actions\Nodes;

use App\Domain\Nodes\RoleAssignmentException;
use App\Domain\Nodes\RoleName;
use App\Domain\Nodes\RoleRegistry;
use App\Models\Node;
use App\Models\NodeRole;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use RuntimeException;

final readonly class AssignRoleAction
{
    public function __construct(
        private RoleRegistry $registry,
    ) {}

    /** @param list<RoleName> $prospectiveRoles */
    public function preflight(Node $node, RoleName $role, array $prospectiveRoles = []): void
    {
        $this->validate($node, $role, $prospectiveRoles);
    }

    public function execute(Node $node, RoleName $role): NodeRole
    {
        try {
            /**
             * @var NodeRole $assignment
             * @mago-expect lint:inline-variable-return The annotation narrows Laravel's transaction result.
             */
            $assignment = DB::transaction(function () use ($node, $role): NodeRole {
                $this->lockRoleClaims();
                $this->validate($node, $role);
                $existing = $node->roles()->where('role', $role->value)->first();

                if ($existing instanceof NodeRole) {
                    return $existing;
                }

                return $node->roles()->create([
                    'role' => $role,
                    'status' => 'provisioning',
                ]);
            });

            return $assignment;
        } catch (UniqueConstraintViolationException) {
            return $node->roles()->where('role', $role->value)->sole();
        }
    }

    private function lockRoleClaims(): void
    {
        $affectedRows = DB::table('nodes')
            ->where('id', '=', static function (Builder $query): void {
                $query
                    ->from('nodes')
                    ->selectRaw('MIN(id)');
            })
            ->update(['id' => DB::raw('id')]);

        if ($affectedRows !== 1) {
            throw new RuntimeException('Could not acquire the node role claim lock.');
        }
    }

    /** @param list<RoleName> $prospectiveRoles */
    private function validate(Node $node, RoleName $role, array $prospectiveRoles = []): void
    {
        $definition = $this->registry->definition($role);

        if ($definition->singleton) {
            $assigned = NodeRole::query()
                ->with('node')
                ->where('role', $role->value)
                ->first();

            if ($assigned instanceof NodeRole && (! $node->exists || $assigned->node_id !== $node->id)) {
                throw new RoleAssignmentException(
                    "Role [{$role->value}] is already assigned to node [{$assigned->node->name}].",
                );
            }
        }

        if ($node->exists) {
            foreach ($node->roles()->where('role', '!=', $role->value)->get() as $assigned) {
                if ($this->registry->conflicts($role, $assigned->role)) {
                    throw new RoleAssignmentException(
                        "Role [{$role->value}] conflicts with assigned role [{$assigned->role->value}].",
                    );
                }
            }
        }

        foreach ($prospectiveRoles as $prospectiveRole) {
            if ($prospectiveRole === $role || ! $this->registry->conflicts($role, $prospectiveRole)) {
                continue;
            }

            throw new RoleAssignmentException(
                "Role [{$role->value}] conflicts with requested role [{$prospectiveRole->value}].",
            );
        }
    }
}
