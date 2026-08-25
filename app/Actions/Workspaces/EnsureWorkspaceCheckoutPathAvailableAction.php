<?php

declare(strict_types=1);

namespace App\Actions\Workspaces;

use App\Domain\Shared\ResourceOperationException;
use App\Models\Instance;
use App\Models\Workspace;

final readonly class EnsureWorkspaceCheckoutPathAvailableAction
{
    public function execute(Instance $instance, Workspace $workspace, string $checkoutPath): void
    {
        $instancePaths = Instance::query()
            ->where('node_id', $instance->node_id)
            ->get(['id', 'checkout_path']);

        foreach ($instancePaths as $managedInstance) {
            $checkoutOwnsInstance =
                $checkoutPath === $managedInstance->checkout_path
                || str_starts_with($managedInstance->checkout_path, $checkoutPath.'/');
            $checkoutIsInsideOtherInstance =
                $managedInstance->id !== $instance->id
                && str_starts_with($checkoutPath, $managedInstance->checkout_path.'/');

            if (! $checkoutOwnsInstance && ! $checkoutIsInsideOtherInstance) {
                continue;
            }

            $this->pathTaken($checkoutPath);
        }

        $workspaces = Workspace::query()
            ->whereHas('instance', static fn ($query) => $query->where('node_id', $instance->node_id))
            ->when($workspace->exists, static fn ($query) => $query->whereKeyNot($workspace->id))
            ->get(['checkout_path']);

        foreach ($workspaces as $managedWorkspace) {
            $managedPath = $managedWorkspace->checkout_path;
            $pathsOverlap =
                $checkoutPath === $managedPath
                || str_starts_with($checkoutPath, $managedPath.'/')
                || str_starts_with($managedPath, $checkoutPath.'/');

            if (! $pathsOverlap) {
                continue;
            }

            $this->pathTaken($checkoutPath);
        }
    }

    private function pathTaken(string $checkoutPath): never
    {
        throw new ResourceOperationException(
            errorCode: 'workspace.path_taken',
            message: "Checkout path [{$checkoutPath}] overlaps another managed checkout on this node.",
            status: 409,
        );
    }
}
