<?php

declare(strict_types=1);

use App\Actions\Nodes\RemoveNodeRoleAction;
use App\Domain\AppDev\AppDevRuntimeConverger;
use App\Domain\AppProd\AppProdRuntimeConverger;
use App\Domain\Instances\CertificateMode;
use App\Domain\Nodes\NodeRoleDependencyInspector;
use App\Domain\Nodes\NodeRoleDependencySet;
use App\Domain\Nodes\NodeRoleDependentCleaner;
use App\Domain\Nodes\NodeRoleOperationException;
use App\Domain\Nodes\NodeRoleValidationException;
use App\Domain\Nodes\RoleBaselineConverger;
use App\Domain\Nodes\RoleName;
use App\Domain\Processes\ProcessOperationException;
use App\Domain\Processes\ProcessRuntimeManager;
use App\Domain\Shared\LifecycleStatus;
use App\Infrastructure\Nodes\NativeNodeRoleDependentCleaner;
use App\Models\App;
use App\Models\Instance;
use App\Models\Node;
use App\Models\NodeRole;
use App\Models\Process;
use App\Models\Workspace;
use Illuminate\Support\Facades\DB;

/** @mago-expect lint:halstead The removal group keeps ordered recovery and failure state observable. */
describe(RemoveNodeRoleAction::class, function (): void {
    it('always returns a no-force preview without mutation even when dependents are empty', function (): void {
        [$node, $assignment] = removal_role_fixture();
        $inspector = new RemovalInspectorFake(new NodeRoleDependencySet([], [], [], []));
        $cleaner = new RemovalCleanerFake;
        $baseline = new RemovalBaselineFake;
        $action = new RemoveNodeRoleAction($inspector, $cleaner, $baseline, app(\App\Domain\Nodes\RoleRegistry::class));

        expect(fn () => $action->execute($node, RoleName::AppDev, force: false, purgeData: false))
            ->toThrow(function (NodeRoleValidationException $exception): void {
                expect($exception->getMessage())
                    ->toBe('Use --force to remove this node role.')
                    ->and($exception->details)
                    ->toBe([
                        'field' => 'force',
                        'reason' => 'destructive_consent_required',
                        'role' => 'app-dev',
                        'dependents' => [],
                    ]);
            });

        expect($assignment->refresh()->status)
            ->toBe(LifecycleStatus::Active)
            ->and($cleaner->calls)
            ->toBe(0)
            ->and($baseline->calls)
            ->toBe(0);
    });

    it('cleans dependents and baseline outside short transactions before deleting records', function (): void {
        [$node, $assignment, $dependencies] = removal_role_fixture(withDependents: true);
        $inspector = new RemovalInspectorFake($dependencies);
        $events = [];
        $cleaner = new RemovalCleanerFake;
        $cleaner->events = &$events;
        $baseline = new RemovalBaselineFake;
        $baseline->events = &$events;
        $action = new RemoveNodeRoleAction($inspector, $cleaner, $baseline, app(\App\Domain\Nodes\RoleRegistry::class));
        $ambientTransactionLevel = DB::transactionLevel();

        $removed = $action->execute($node, RoleName::AppDev, force: true, purgeData: true);

        expect($removed)
            ->toBe($dependencies)
            ->and($events)
            ->toBe([
                "clean:{$ambientTransactionLevel}",
                "baseline:1:{$ambientTransactionLevel}",
            ])
            ->and($cleaner->observedStatuses)
            ->toBe([
                LifecycleStatus::Removing,
                LifecycleStatus::Removing,
                LifecycleStatus::Removing,
            ])
            ->and(NodeRole::query()->whereKey($assignment->id)->exists())
            ->toBeFalse();

        expect(removal_dependency_rows_exist($dependencies))->toBeFalse();
    });

    it('keeps every row retryable when a remote stage fails', function (string $step): void {
        [$node, $assignment, $dependencies] = removal_role_fixture(withDependents: true);
        $inspector = new RemovalInspectorFake($dependencies);
        $cleaner = new RemovalCleanerFake;
        $baseline = new RemovalBaselineFake;

        if ($step === 'baseline') {
            $baseline->failure = new \RuntimeException('baseline failed');
        }

        if ($step !== 'baseline') {
            $cleaner->failure = new \App\Domain\AppDev\RuntimeConvergenceException(
                step: $step,
                errorCode: "cleanup.{$step}_failed",
                message: "{$step} failed",
            );
        }

        $action = new RemoveNodeRoleAction($inspector, $cleaner, $baseline, app(\App\Domain\Nodes\RoleRegistry::class));

        expect(fn () => $action->execute($node, RoleName::AppDev, force: true, purgeData: false))
            ->toThrow(NodeRoleOperationException::class);

        expect($assignment->refresh()->status)
            ->toBe(LifecycleStatus::Failed)
            ->and($assignment->failed_step)
            ->toBe("remove:{$step}")
            ->and(removal_dependency_rows_exist($dependencies))
            ->toBeTrue();

        $cleaner->failure = null;
        $baseline->failure = null;
        $removed = $action->execute($node, RoleName::AppDev, force: true, purgeData: false);

        expect($removed)
            ->toBe($dependencies)
            ->and(NodeRole::query()->whereKey($assignment->id)->exists())
            ->toBeFalse()
            ->and(removal_dependency_rows_exist($dependencies))
            ->toBeFalse();
    })->with([
        'process runtime' => 'process-runtime',
        'workspace publication' => 'workspace-runtime',
        'instance publication' => 'instance-runtime',
        'role baseline' => 'baseline',
    ]);

    it('stops finalization when a new dependent appears and removes it on retry', function (): void {
        [$node, $assignment, $dependencies] = removal_role_fixture(withDependents: true);
        $inspector = app(NodeRoleDependencyInspector::class);
        $cleaner = new RemovalCleanerFake;
        $cleaner->afterClean = function () use ($dependencies): void {
            $instance = \App\Models\Instance::query()->findOrFail($dependencies->instanceIds[0]);
            removal_process(owner: $instance, name: 'late-process', status: LifecycleStatus::Active);
        };
        $baseline = new RemovalBaselineFake;
        $action = new RemoveNodeRoleAction($inspector, $cleaner, $baseline, app(\App\Domain\Nodes\RoleRegistry::class));

        expect(fn () => $action->execute($node, RoleName::AppDev, force: true, purgeData: false))
            ->toThrow(NodeRoleOperationException::class);

        expect($assignment->refresh()->failed_step)
            ->toBe('remove:dependency-race')
            ->and(removal_dependency_rows_exist($dependencies))
            ->toBeTrue();

        $cleaner->afterClean = null;
        $action->execute($node, RoleName::AppDev, force: true, purgeData: false);

        expect($node->roles()->where('role', RoleName::AppDev->value)->exists())
            ->toBeFalse()
            ->and($node->instances()->exists())
            ->toBeFalse();
    });

    it('records the exact failure on the dependent that could not be cleaned', function (string $stage): void {
        [, , $dependencies] = removal_role_fixture(withDependents: true);
        Process::query()->whereIn('id', $dependencies->processIds)->update(['status' => LifecycleStatus::Removing]);
        Workspace::query()->whereIn('id', $dependencies->workspaceIds)->update(['status' => LifecycleStatus::Removing]);
        Instance::query()->whereIn('id', $dependencies->instanceIds)->update(['status' => LifecycleStatus::Removing]);
        $processes = Mockery::mock(ProcessRuntimeManager::class);
        $processes
            ->shouldReceive('remove')
            ->once()
            ->andReturnUsing(function () use ($stage): void {
                if ($stage === 'process-runtime') {
                    throw new ProcessOperationException('stop', 'process.stop_failed', 'stop failed');
                }
            });
        $appDev = Mockery::mock(AppDevRuntimeConverger::class);
        $appDev
            ->shouldReceive('unpublishWorkspace')
            ->times($stage === 'process-runtime' ? 0 : 1)
            ->andReturnUsing(function () use ($stage): void {
                if ($stage === 'workspace-runtime') {
                    throw new \App\Domain\AppDev\RuntimeConvergenceException(
                        'private-dns',
                        'app-dev.dns_config_failed',
                        'DNS failed',
                    );
                }
            });
        $appDev
            ->shouldReceive('unpublishInstance')
            ->times($stage === 'instance-runtime' ? 1 : 0)
            ->andThrow(new \App\Domain\AppDev\RuntimeConvergenceException(
                'certificate',
                'app-dev.certificate_remove_failed',
                'Certificate failed',
            ));
        $cleaner = new NativeNodeRoleDependentCleaner(
            processes: $processes,
            appDev: $appDev,
            appProd: Mockery::mock(AppProdRuntimeConverger::class),
        );

        expect(fn () => $cleaner->clean($dependencies))->toThrow(NodeRoleOperationException::class);

        $failed = match ($stage) {
            'process-runtime' => Process::query()->findOrFail($dependencies->processIds[0]),
            'workspace-runtime' => Workspace::query()->findOrFail($dependencies->workspaceIds[0]),
            'instance-runtime' => Instance::query()->findOrFail($dependencies->instanceIds[0]),
        };
        $expected = match ($stage) {
            'process-runtime' => ['stop', 'process.stop_failed'],
            'workspace-runtime' => ['private-dns', 'app-dev.dns_config_failed'],
            'instance-runtime' => ['certificate', 'app-dev.certificate_remove_failed'],
        };

        expect($failed->status)
            ->toBe(LifecycleStatus::Failed)
            ->and($failed->failed_step)
            ->toBe($expected[0])
            ->and($failed->error_code)
            ->toBe($expected[1]);
    })->with(['process-runtime', 'workspace-runtime', 'instance-runtime']);
});

/**
 * @return array{Node, NodeRole, 2?: NodeRoleDependencySet}
 * @mago-expect lint:no-boolean-flag-parameter The fixture optionally creates the dependent graph under test.
 */
function removal_role_fixture(bool $withDependents = false): array
{
    $node = removal_node('remove-node-'.strtolower(fake()->bothify('??##')));
    $assignment = $node->roles()->create([
        'role' => RoleName::AppDev,
        'status' => LifecycleStatus::Active,
    ]);

    if (! $withDependents) {
        return [$node, $assignment];
    }

    $instance = removal_instance(
        node: $node,
        slug: 'remove-app-'.strtolower(fake()->bothify('??##')),
        certificateMode: CertificateMode::OrbitCa,
        environment: 'development',
    );
    $workspace = removal_workspace(instance: $instance, name: 'feature', status: LifecycleStatus::Active);
    $process = removal_process(owner: $workspace, name: 'worker', status: LifecycleStatus::Active);
    $dependencies = new NodeRoleDependencySet(
        instanceIds: [$instance->id],
        workspaceIds: [$workspace->id],
        processIds: [$process->id],
        summaries: ['1 development instance record', '1 process record', '1 workspace record'],
    );

    return [$node, $assignment, $dependencies];
}

function removal_node(string $name): Node
{
    return Node::query()->create([
        'name' => $name,
        'status' => LifecycleStatus::Active,
        'platform' => 'linux',
        'public_ssh_host' => '192.0.2.91',
    ]);
}

function removal_instance(
    Node $node,
    string $slug,
    CertificateMode $certificateMode,
    string $environment,
): Instance {
    $app = App::query()->create([
        'name' => ucfirst($slug),
        'slug' => $slug,
        'repository_url' => "git@example.test:{$slug}.git",
    ]);

    return Instance::query()->create([
        'app_id' => $app->id,
        'node_id' => $node->id,
        'name' => 'main',
        'environment' => $environment,
        'checkout_path' => "/srv/{$slug}",
        'document_root' => 'public',
        'php_version' => '8.5',
        'hostname' => "{$slug}.example.test",
        'certificate_mode' => $certificateMode,
        'status' => LifecycleStatus::Active,
    ]);
}

function removal_workspace(Instance $instance, string $name, LifecycleStatus $status): Workspace
{
    return Workspace::query()->create([
        'instance_id' => $instance->id,
        'name' => $name,
        'branch' => $name,
        'checkout_path' => "{$instance->checkout_path}/{$name}",
        'hostname' => "{$name}.{$instance->hostname}",
        'status' => $status,
    ]);
}

function removal_process(Instance|Workspace $owner, string $name, LifecycleStatus $status): Process
{
    return Process::query()->create([
        'owner_type' => $owner::class,
        'owner_id' => $owner->id,
        'name' => $name,
        'runtime' => 'systemd',
        'working_directory' => $owner->checkout_path,
        'runtime_config' => ['command' => ['/usr/bin/true']],
        'restart_policy' => 'never',
        'desired_state' => 'stopped',
        'status' => $status,
    ]);
}

function removal_dependency_rows_exist(NodeRoleDependencySet $dependencies): bool
{
    return (
        \App\Models\Instance::query()->whereIn('id', $dependencies->instanceIds)->exists()
        && \App\Models\Workspace::query()->whereIn('id', $dependencies->workspaceIds)->exists()
        && \App\Models\Process::query()->whereIn('id', $dependencies->processIds)->exists()
    );
}

final class RemovalInspectorFake implements NodeRoleDependencyInspector
{
    public function __construct(
        public NodeRoleDependencySet $dependencies,
    ) {}

    public function inspect(Node $node, RoleName $role): NodeRoleDependencySet
    {
        return $this->dependencies;
    }
}

/** @mago-expect lint:single-class-per-file Small test fakes stay next to their single consumer. */
final class RemovalCleanerFake implements NodeRoleDependentCleaner
{
    public int $calls = 0;

    /** @var list<LifecycleStatus> */
    public array $observedStatuses = [];

    public ?Throwable $failure = null;

    public ?Closure $afterClean = null;

    /** @var list<string> */
    public array $events = [];

    public function clean(NodeRoleDependencySet $dependencies): void
    {
        $this->calls++;
        $this->events[] = 'clean:'.DB::transactionLevel();
        $this->observedStatuses = [
            \App\Models\Process::query()->findOrFail($dependencies->processIds[0])->status,
            \App\Models\Workspace::query()->findOrFail($dependencies->workspaceIds[0])->status,
            \App\Models\Instance::query()->findOrFail($dependencies->instanceIds[0])->status,
        ];

        if ($this->failure instanceof Throwable) {
            throw $this->failure;
        }

        if ($this->afterClean instanceof Closure) {
            ($this->afterClean)();
        }
    }
}

/** @mago-expect lint:single-class-per-file Small test fakes stay next to their single consumer. */
final class RemovalBaselineFake implements RoleBaselineConverger
{
    public int $calls = 0;

    public ?Throwable $failure = null;

    /** @var list<string> */
    public array $events = [];

    public function converge(Node $node, NodeRole $assignment): void {}

    public function remove(Node $node, NodeRole $assignment, bool $purgeData): void
    {
        $this->calls++;
        $this->events[] = 'baseline:'.(int) $purgeData.':'.DB::transactionLevel();

        if ($this->failure instanceof Throwable) {
            throw $this->failure;
        }
    }
}
