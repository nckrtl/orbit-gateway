<?php

declare(strict_types=1);

namespace App\Domain\Processes;

use App\Domain\AppDev\AppDevHostPaths;
use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Domain\Shared\ResourceOperationException;
use App\Models\Instance;
use App\Models\Process;
use App\Models\Workspace;
use SensitiveParameter;

final readonly class ProcessTargetResolver
{
    public function __construct(
        private AppDevHostPaths $paths = new AppDevHostPaths,
    ) {}

    public function resolve(ProcessTargetType $type, int $id): ProcessTarget
    {
        return match ($type) {
            ProcessTargetType::Instance => $this->instance(
                Instance::query()
                    ->with(['app', 'node.roles'])
                    ->findOrFail($id),
            ),
            ProcessTargetType::Workspace => $this->workspace(
                Workspace::query()
                    ->with(['instance.app', 'instance.node.roles'])
                    ->findOrFail($id),
            ),
        };
    }

    public function forProcess(#[SensitiveParameter] Process $process): ProcessTarget
    {
        return $this->resolve(
            ProcessTargetType::fromModelClass($process->owner_type),
            $process->owner_id,
        );
    }

    private function instance(Instance $instance): ProcessTarget
    {
        $this->ensureActive($instance);

        if ($instance->node->platform === 'darwin') {
            return new ProcessTarget(
                node: $instance->node,
                user: $instance->node->ssh_user,
                checkoutPath: $this->paths->instanceCheckout(
                    $instance->node,
                    RoleName::AppDev,
                    $instance->app->slug,
                    $instance->name,
                ),
            );
        }

        $user = $this->hasActiveAppProdRole($instance)
            ? "orbit-{$instance->app->slug}"
            : 'orbit';

        return new ProcessTarget(
            node: $instance->node,
            user: $user,
            checkoutPath: $instance->checkout_path,
        );
    }

    private function workspace(Workspace $workspace): ProcessTarget
    {
        $this->ensureActive($workspace->instance);

        if ($this->hasActiveAppProdRole($workspace->instance)) {
            throw new ResourceOperationException(
                errorCode: 'process.workspace_not_allowed',
                message: 'Workspaces cannot run processes on app-prod nodes.',
            );
        }

        if ($workspace->status !== LifecycleStatus::Active) {
            throw new ResourceOperationException(
                errorCode: 'process.target_inactive',
                message: "Workspace [{$workspace->name}] is not active.",
            );
        }

        if ($workspace->instance->node->platform === 'darwin') {
            return new ProcessTarget(
                node: $workspace->instance->node,
                user: $workspace->instance->node->ssh_user,
                checkoutPath: $this->paths->workspaceCheckout(
                    $workspace->instance->node,
                    $workspace->instance->app->slug,
                    $workspace->name,
                ),
            );
        }

        return new ProcessTarget(
            node: $workspace->instance->node,
            user: 'orbit',
            checkoutPath: $workspace->checkout_path,
        );
    }

    private function ensureActive(Instance $instance): void
    {
        if (
            ! in_array($instance->node->platform, ['linux', 'darwin'], strict: true)
            || ! $this->hasSupportedRole($instance)
        ) {
            throw new ResourceOperationException(
                errorCode: 'process.platform_unsupported',
                message: "Processes are not supported on [{$instance->node->platform}] nodes yet.",
            );
        }

        if ($instance->status === LifecycleStatus::Active && $instance->node->status === LifecycleStatus::Active) {
            return;
        }

        throw new ResourceOperationException(
            errorCode: 'process.target_inactive',
            message: "Instance [{$instance->name}] or its node is not active.",
        );
    }

    private function hasActiveAppProdRole(Instance $instance): bool
    {
        return $instance
            ->node
            ->roles
            ->contains(
                static fn ($role): bool => (
                    $role->role === RoleName::AppProd
                    && $role->status === LifecycleStatus::Active
                ),
            );
    }

    private function hasSupportedRole(Instance $instance): bool
    {
        if ($instance->node->platform === 'darwin') {
            $this->paths->home($instance->node, RoleName::AppDev);

            return $instance
                ->node
                ->roles
                ->contains(
                    static fn ($role): bool => (
                        $role->role === RoleName::AppDev
                        && $role->status === LifecycleStatus::Active
                    ),
                );
        }

        return $instance
            ->node
            ->roles
            ->contains(
                static fn ($role): bool => (
                    in_array($role->role, [RoleName::AppDev, RoleName::AppProd], strict: true)
                    && $role->status === LifecycleStatus::Active
                ),
            );
    }
}
