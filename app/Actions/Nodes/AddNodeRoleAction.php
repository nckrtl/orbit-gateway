<?php

declare(strict_types=1);

namespace App\Actions\Nodes;

use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\Firewall\FirewallOperationException;
use App\Domain\Nodes\NodeRoleOperationException;
use App\Domain\Nodes\RoleAssignmentException;
use App\Domain\Nodes\RoleBaselineConverger;
use App\Domain\Nodes\RoleName;
use App\Domain\Nodes\RoleRegistry;
use App\Domain\Shared\LifecycleStatus;
use App\Models\Node;
use App\Models\NodeRole;
use Illuminate\Support\Facades\DB;
use Throwable;

final readonly class AddNodeRoleAction
{
    public function __construct(
        private AssignRoleAction $assignRole,
        private RoleRegistry $registry,
        private RoleBaselineConverger $baselines,
    ) {}

    /**
     * @return array{assignment: NodeRole, created: bool}
     * @mago-expect lint:no-boolean-flag-parameter The saved public contract exposes explicit reconvergence.
     */
    public function execute(Node $node, RoleName $role, bool $convergeExisting = false): array
    {
        $this->guardActiveNode($node);

        if (! $this->registry->definition($role)->mutable) {
            throw new RoleAssignmentException("Role [{$role->value}] is protected from generic mutation.");
        }

        $claim = $convergeExisting
            ? $this->claimExisting($node, $role)
            : $this->claimNew($node, $role);

        return $this->convergeClaim($node, $role, $claim);
    }

    public function executeDuringProvisioning(Node $node, RoleName $role): NodeRole
    {
        $this->guardActiveNode($node);

        if (! $this->registry->definition($role)->assignableDuringProvisioning) {
            throw new RoleAssignmentException("Role [{$role->value}] cannot be assigned during provisioning.");
        }

        return $this->convergeClaim($node, $role, $this->claimExisting($node, $role))['assignment'];
    }

    /** @param list<RoleName> $prospectiveRoles */
    public function preflightDuringProvisioning(Node $node, RoleName $role, array $prospectiveRoles): void
    {
        if (! $this->registry->definition($role)->assignableDuringProvisioning) {
            throw new RoleAssignmentException("Role [{$role->value}] cannot be assigned during provisioning.");
        }

        $this->assignRole->preflight($node, $role, $prospectiveRoles);
    }

    /** @return array{assignment: NodeRole, created: bool} */
    private function claimNew(Node $node, RoleName $role): array
    {
        /**
         * @var array{assignment: NodeRole, created: bool} $claim
         * @mago-expect lint:inline-variable-return The annotation narrows Laravel's transaction result.
         */
        $claim = DB::transaction(function () use ($node, $role): array {
            $assignment = $this->assignRole->execute($node, $role);

            if (! $assignment->wasRecentlyCreated) {
                throw new RoleAssignmentException(
                    "Role [{$role->value}] is already assigned; explicit convergence is required.",
                );
            }

            return ['assignment' => $assignment, 'created' => true];
        });

        return $claim;
    }

    /** @return array{assignment: NodeRole, created: bool} */
    private function claimExisting(Node $node, RoleName $role): array
    {
        /**
         * @var array{assignment: NodeRole, created: bool} $claim
         * @mago-expect lint:inline-variable-return The annotation narrows Laravel's transaction result.
         */
        $claim = DB::transaction(function () use ($node, $role): array {
            $assignment = $this->assignRole->execute($node, $role);

            if ($assignment->wasRecentlyCreated) {
                return ['assignment' => $assignment, 'created' => true];
            }

            $assignment->refresh();

            if (! $assignment->canClaimConvergence()) {
                throw new RoleAssignmentException(
                    "Role [{$role->value}] cannot converge from status [{$assignment->status->value}].",
                );
            }

            $assignment->claimConvergence();

            return ['assignment' => $assignment, 'created' => false];
        });

        return $claim;
    }

    /**
     * @param  array{assignment: NodeRole, created: bool}  $claim
     * @return array{assignment: NodeRole, created: bool}
     */
    private function convergeClaim(Node $node, RoleName $role, array $claim): array
    {
        try {
            $this->baselines->converge($node, $claim['assignment']);
        } catch (NodeRoleOperationException $exception) {
            $step = $this->unnamespacedStep($exception->step);

            $this->failConvergence($claim['assignment'], new NodeRoleOperationException(
                step: $step,
                errorCode: 'node_role.convergence_failed',
                underlyingErrorCode: $exception->underlyingErrorCode,
                message: $exception->getMessage(),
                result: $exception->result,
                previous: $exception,
            ));
        } catch (RuntimeConvergenceException|FirewallOperationException $exception) {
            $this->failConvergence($claim['assignment'], new NodeRoleOperationException(
                step: $this->unnamespacedStep($exception->step),
                errorCode: 'node_role.convergence_failed',
                underlyingErrorCode: $exception->errorCode,
                message: $exception->getMessage(),
                result: $exception->result,
                previous: $exception,
            ));
        } catch (Throwable $exception) {
            $this->failConvergence($claim['assignment'], new NodeRoleOperationException(
                step: 'baseline',
                errorCode: 'node_role.convergence_failed',
                underlyingErrorCode: 'node_role.convergence_unknown',
                message: "Role [{$role->value}] convergence failed on node [{$node->name}].",
                previous: $exception,
            ));
        }

        DB::transaction(static fn () => $claim['assignment']->markConvergenceActive());

        return [
            'assignment' => $claim['assignment']->refresh(),
            'created' => $claim['created'],
        ];
    }

    private function guardActiveNode(Node $node): void
    {
        if (! $node->exists || $node->status !== LifecycleStatus::Active) {
            throw new RoleAssignmentException('Roles can be changed only on an active node.');
        }
    }

    private function unnamespacedStep(string $step): string
    {
        return str_starts_with($step, 'converge:') ? substr($step, offset: 9) : $step;
    }

    private function failConvergence(NodeRole $assignment, NodeRoleOperationException $exception): never
    {
        DB::transaction(static fn () => $assignment->markConvergenceFailed(
            $exception->step,
            $exception->underlyingErrorCode,
        ));

        throw new NodeRoleOperationException(
            step: "converge:{$exception->step}",
            errorCode: $exception->errorCode,
            underlyingErrorCode: $exception->underlyingErrorCode,
            message: $exception->getMessage(),
            result: $exception->result,
            previous: $exception->getPrevious(),
        );
    }
}
