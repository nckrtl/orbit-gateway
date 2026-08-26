<?php

declare(strict_types=1);

namespace App\Actions\Workspaces;

use App\Data\Workspaces\CreateWorkspaceData;
use App\Domain\AppDev\AppDevRuntimeConverger;
use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Domain\Shared\ResourceOperationException;
use App\Models\Instance;
use App\Models\Workspace;
use Throwable;

final readonly class CreateWorkspaceAction
{
    public function __construct(
        private AppDevRuntimeConverger $runtime,
        private EnsureWorkspaceCheckoutPathAvailableAction $ensureCheckoutPathAvailable,
    ) {}

    /** @return array{workspace: Workspace, created: bool} */
    public function execute(CreateWorkspaceData $data): array
    {
        $instance = Instance::query()->with(['app', 'node.roles'])->findOrFail($data->instanceId);
        $this->ensureAppDevInstance($instance);
        $workspace = Workspace::query()->firstOrNew([
            'instance_id' => $instance->id,
            'name' => $data->name,
        ]);
        $created = ! $workspace->exists;
        $checkoutPath = $data->checkoutPath ?? "/home/orbit/.orbit/worktrees/{$instance->app->slug}/{$data->name}";
        $hostname = "{$data->name}.{$instance->hostname}";

        if (filter_var($hostname, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
            throw new ResourceOperationException(
                errorCode: 'workspace.hostname_invalid',
                message: "Derived hostname [{$hostname}] is invalid.",
            );
        }

        if ($workspace->exists && $workspace->checkout_path !== $checkoutPath) {
            throw new ResourceOperationException(
                errorCode: 'workspace.path_change_unsupported',
                message: "Workspace [{$workspace->name}] cannot change its checkout path.",
                status: 409,
            );
        }

        if ($workspace->exists && $workspace->branch !== $data->branch) {
            throw new ResourceOperationException(
                errorCode: 'workspace.branch_change_unsupported',
                message: "Workspace [{$workspace->name}] cannot change its branch.",
                status: 409,
            );
        }

        $this->ensureCheckoutPathAvailable->execute($instance, $workspace, $checkoutPath);
        $collision = Workspace::query()
            ->where('hostname', $hostname)
            ->when($workspace->exists, static fn ($query) => $query->whereKeyNot($workspace->id))
            ->exists();

        if ($collision) {
            throw new ResourceOperationException(
                errorCode: 'workspace.hostname_taken',
                message: "Hostname [{$hostname}] is already in use.",
                status: 409,
            );
        }

        $workspace->fill([
            'branch' => $data->branch,
            'checkout_path' => $checkoutPath,
            'php_version' => $data->phpVersion,
            'hostname' => $hostname,
            'status' => LifecycleStatus::Provisioning,
            'failed_step' => null,
            'error_code' => null,
        ])->save();

        try {
            $this->runtime->convergeWorkspace($workspace->refresh()->load('instance.node'));
        } catch (RuntimeConvergenceException $exception) {
            $this->markFailed($workspace, $exception);

            throw $exception;
        } catch (Throwable $exception) {
            $failure = new RuntimeConvergenceException(
                step: 'unknown',
                errorCode: 'workspace.provision_failed',
                message: 'Workspace provisioning failed.',
                previous: $exception,
            );
            $this->markFailed($workspace, $failure);

            throw $failure;
        }

        $workspace->update([
            'status' => LifecycleStatus::Active,
            'failed_step' => null,
            'error_code' => null,
        ]);

        return ['workspace' => $workspace->refresh()->load('instance'), 'created' => $created];
    }

    private function ensureAppDevInstance(Instance $instance): void
    {
        $hasAppProdRole = $instance
            ->node
            ->roles
            ->contains(
                static fn ($role): bool => (
                    $role->role === RoleName::AppProd
                    && $role->status === LifecycleStatus::Active
                ),
            );

        if ($hasAppProdRole) {
            throw new ResourceOperationException(
                errorCode: 'workspace.unsupported_for_app_prod',
                message: "Instance [{$instance->name}] is on an app-prod node, which does not support workspaces.",
            );
        }

        $hasRole = $instance->node->status === LifecycleStatus::Active
        && $instance
            ->node
            ->roles
            ->contains(
                static fn ($role): bool => (
                    $role->role === RoleName::AppDev
                    && $role->status === LifecycleStatus::Active
                ),
            );

        if ($hasRole) {
            return;
        }

        throw new ResourceOperationException(
            errorCode: 'workspace.node_not_app_dev',
            message: "Instance [{$instance->name}] is not on an active app-dev node.",
        );
    }

    private function markFailed(Workspace $workspace, RuntimeConvergenceException $exception): void
    {
        $workspace->update([
            'status' => LifecycleStatus::Failed,
            'failed_step' => $exception->step,
            'error_code' => $exception->errorCode,
        ]);
    }
}
