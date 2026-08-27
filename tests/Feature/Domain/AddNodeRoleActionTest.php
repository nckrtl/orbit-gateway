<?php

declare(strict_types=1);

use App\Actions\Nodes\AddNodeRoleAction;
use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\Nodes\NodeRoleOperationException;
use App\Domain\Nodes\RoleAssignmentException;
use App\Domain\Nodes\RoleBaselineConverger;
use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Models\Node;
use App\Models\NodeRole;
use Illuminate\Support\Facades\DB;

/** @mago-expect lint:halstead The focused group keeps each role lifecycle transition visible. */
describe(AddNodeRoleAction::class, function (): void {
    it('creates and converges a mutable role outside a database transaction', function (): void {
        expect(class_exists(AddNodeRoleAction::class))->toBeTrue();

        $baseline = new AddNodeRoleBaselineFake;
        app()->instance(RoleBaselineConverger::class, $baseline);
        $node = add_role_node();

        $ambientTransactionLevel = DB::transactionLevel();
        $result = app(AddNodeRoleAction::class)->execute($node, RoleName::AppDev);

        expect($result['created'])
            ->toBeTrue()
            ->and($result['assignment']->status)
            ->toBe(LifecycleStatus::Active)
            ->and($baseline->convergedRoles)
            ->toBe([RoleName::AppDev])
            ->and($baseline->observedStatuses)
            ->toBe([LifecycleStatus::Provisioning])
            ->and($baseline->transactionLevels)
            ->toBe([$ambientTransactionLevel])
            ->and($node->refresh()->status)
            ->toBe(LifecycleStatus::Active);
    });

    it('rejects a mutable role when the node is not active before baseline effects', function (): void {
        $baseline = new AddNodeRoleBaselineFake;
        app()->instance(RoleBaselineConverger::class, $baseline);
        $node = add_role_node(LifecycleStatus::Provisioning);

        expect(fn () => app(AddNodeRoleAction::class)->execute($node, RoleName::AppDev))
            ->toThrow(RoleAssignmentException::class);

        expect($baseline->convergedRoles)
            ->toBeEmpty()
            ->and($node->roles()->exists())
            ->toBeFalse();
    });

    it('rejects protected roles before baseline effects', function (RoleName $role): void {
        $baseline = new AddNodeRoleBaselineFake;
        app()->instance(RoleBaselineConverger::class, $baseline);
        $node = add_role_node();

        expect(fn () => app(AddNodeRoleAction::class)->execute($node, $role))
            ->toThrow(RoleAssignmentException::class);

        expect($baseline->convergedRoles)
            ->toBeEmpty()
            ->and($node->roles()->exists())
            ->toBeFalse();
    })->with([
        'gateway' => RoleName::Gateway,
        'VPN' => RoleName::Vpn,
    ]);

    it('rejects an existing assignment unless convergence is explicit', function (): void {
        $baseline = new AddNodeRoleBaselineFake;
        app()->instance(RoleBaselineConverger::class, $baseline);
        $node = add_role_node();
        $assignment = $node->roles()->create([
            'role' => RoleName::AppDev,
            'status' => LifecycleStatus::Active,
        ]);

        expect(fn () => app(AddNodeRoleAction::class)->execute($node, RoleName::AppDev))
            ->toThrow(RoleAssignmentException::class);

        expect($baseline->convergedRoles)
            ->toBeEmpty()
            ->and($assignment->refresh()->status)
            ->toBe(LifecycleStatus::Active);
    });

    it('reconverges eligible existing assignments and clears old failures', function (
        LifecycleStatus $status,
        ?string $failedStep,
    ): void {
        $baseline = new AddNodeRoleBaselineFake;
        app()->instance(RoleBaselineConverger::class, $baseline);
        $node = add_role_node();
        $assignment = $node->roles()->create([
            'role' => RoleName::AppDev,
            'status' => $status,
            'failed_step' => $failedStep,
            'error_code' => $failedStep === null ? null : 'app-dev.caddy_config_failed',
        ]);

        $ambientTransactionLevel = DB::transactionLevel();
        $result = app(AddNodeRoleAction::class)->execute($node, RoleName::AppDev, convergeExisting: true);

        expect($result['created'])
            ->toBeFalse()
            ->and($result['assignment']->is($assignment))
            ->toBeTrue()
            ->and($assignment->refresh()->status)
            ->toBe(LifecycleStatus::Active)
            ->and($assignment->failed_step)
            ->toBeNull()
            ->and($assignment->error_code)
            ->toBeNull()
            ->and($baseline->transactionLevels)
            ->toBe([$ambientTransactionLevel]);
    })->with([
        'active assignment' => [LifecycleStatus::Active, null],
        'failed convergence' => [LifecycleStatus::Failed, 'converge:caddy-config'],
    ]);

    it('rejects assignments that are busy or failed during removal', function (
        LifecycleStatus $status,
        ?string $failedStep,
    ): void {
        $baseline = new AddNodeRoleBaselineFake;
        app()->instance(RoleBaselineConverger::class, $baseline);
        $node = add_role_node();
        $assignment = $node->roles()->create([
            'role' => RoleName::AppDev,
            'status' => $status,
            'failed_step' => $failedStep,
            'error_code' => $failedStep === null ? null : 'app-dev.remove_failed',
        ]);

        expect(fn () => app(AddNodeRoleAction::class)->execute($node, RoleName::AppDev, convergeExisting: true))
            ->toThrow(RoleAssignmentException::class);

        expect($baseline->convergedRoles)
            ->toBeEmpty()
            ->and($assignment->refresh()->status)
            ->toBe($status)
            ->and($assignment->failed_step)
            ->toBe($failedStep);
    })->with([
        'provisioning assignment' => [LifecycleStatus::Provisioning, null],
        'removing assignment' => [LifecycleStatus::Removing, null],
        'failed removal' => [LifecycleStatus::Failed, 'remove:caddy-config'],
    ]);

    it('rejects same-node role conflicts before baseline effects', function (): void {
        $baseline = new AddNodeRoleBaselineFake;
        app()->instance(RoleBaselineConverger::class, $baseline);
        $node = add_role_node();
        $node->roles()->create(['role' => RoleName::AppProd, 'status' => LifecycleStatus::Active]);

        expect(fn () => app(AddNodeRoleAction::class)->execute($node, RoleName::AppDev))
            ->toThrow(RoleAssignmentException::class);

        expect($baseline->convergedRoles)->toBeEmpty();
    });

    it('rechecks singleton ownership during a provisioning claim', function (): void {
        $baseline = new AddNodeRoleBaselineFake;
        app()->instance(RoleBaselineConverger::class, $baseline);
        $first = add_role_node(name: 'first');
        $second = add_role_node(name: 'second', wireguardAddress: '10.44.0.3');
        $first->roles()->create(['role' => RoleName::Gateway, 'status' => LifecycleStatus::Active]);

        expect(fn () => app(AddNodeRoleAction::class)->executeDuringProvisioning($second, RoleName::Gateway))
            ->toThrow(RoleAssignmentException::class);

        expect($baseline->convergedRoles)
            ->toBeEmpty()
            ->and($second->roles()->exists())
            ->toBeFalse();
    });

    it('stores a namespaced convergence failure while the node stays active', function (): void {
        $baseline = new AddNodeRoleBaselineFake;
        $baseline->failure = new RuntimeConvergenceException(
            step: 'caddy-config',
            errorCode: 'app-dev.caddy_config_failed',
            message: 'Caddy failed.',
        );
        app()->instance(RoleBaselineConverger::class, $baseline);
        $node = add_role_node();
        $ambientTransactionLevel = DB::transactionLevel();

        expect(fn () => app(AddNodeRoleAction::class)->execute($node, RoleName::AppDev))
            ->toThrow(function (NodeRoleOperationException $exception): void {
                expect($exception->step)
                    ->toBe('converge:caddy-config')
                    ->and($exception->errorCode)
                    ->toBe('node_role.convergence_failed')
                    ->and($exception->underlyingErrorCode)
                    ->toBe('app-dev.caddy_config_failed');
            });

        $assignment = $node->roles()->sole();

        expect($node->refresh()->status)
            ->toBe(LifecycleStatus::Active)
            ->and($assignment->status)
            ->toBe(LifecycleStatus::Failed)
            ->and($assignment->failed_step)
            ->toBe('converge:caddy-config')
            ->and($assignment->error_code)
            ->toBe('app-dev.caddy_config_failed')
            ->and($baseline->transactionLevels)
            ->toBe([$ambientTransactionLevel]);
    });
});

function add_role_node(
    LifecycleStatus $status = LifecycleStatus::Active,
    string $name = 'app-host',
    string $wireguardAddress = '10.44.0.2',
): Node {
    return Node::query()->create([
        'name' => $name,
        'status' => $status,
        'platform' => 'linux',
        'architecture' => 'x86_64',
        'public_ssh_host' => '192.0.2.10',
        'ssh_user' => 'orbit',
        'wireguard_address' => $wireguardAddress,
    ]);
}

/** @mago-expect lint:file-name The focused fake records role convergence boundaries. */
final class AddNodeRoleBaselineFake implements RoleBaselineConverger
{
    /** @var list<RoleName> */
    public array $convergedRoles = [];

    /** @var list<LifecycleStatus> */
    public array $observedStatuses = [];

    /** @var list<int> */
    public array $transactionLevels = [];

    public ?Throwable $failure = null;

    public function converge(Node $node, NodeRole $assignment): void
    {
        $this->convergedRoles[] = $assignment->role;
        $this->observedStatuses[] = $assignment->status;
        $this->transactionLevels[] = DB::transactionLevel();

        if ($this->failure instanceof Throwable) {
            throw $this->failure;
        }
    }

    public function remove(Node $node, NodeRole $assignment, bool $purgeData): void {}
}
