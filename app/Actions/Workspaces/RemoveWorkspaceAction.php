<?php

declare(strict_types=1);

namespace App\Actions\Workspaces;

use App\Domain\AppDev\AppDevRuntimeConverger;
use App\Domain\AppDev\AppDevSourceOperationLock;
use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\Shared\LifecycleStatus;
use App\Domain\Shared\ResourceOperationException;
use App\Models\Workspace;
use Throwable;

final readonly class RemoveWorkspaceAction
{
    public function __construct(
        private AppDevRuntimeConverger $runtime,
        private AppDevSourceOperationLock $sourceLock,
    ) {}

    public function execute(Workspace $workspace): Workspace
    {
        $workspace->loadMissing('instance.node');

        return $this->sourceLock->synchronized(
            $workspace->instance->node_id,
            fn (): Workspace => $this->executeWithinSourceLock($workspace),
        );
    }

    private function executeWithinSourceLock(Workspace $workspace): Workspace
    {
        if ($workspace->processes()->exists()) {
            throw new ResourceOperationException(
                errorCode: 'workspace.has_processes',
                message: "Workspace [{$workspace->name}] still has processes.",
                status: 409,
            );
        }

        $workspace->update(['status' => LifecycleStatus::Removing]);

        try {
            $this->runtime->removeWorkspace($workspace);
        } catch (RuntimeConvergenceException $exception) {
            $this->markFailed($workspace, $exception);

            throw $exception;
        } catch (Throwable $exception) {
            $failure = new RuntimeConvergenceException(
                step: 'unknown',
                errorCode: 'workspace.remove_failed',
                message: 'Workspace removal failed.',
                previous: $exception,
            );
            $this->markFailed($workspace, $failure);

            throw $failure;
        }

        $workspace->delete();

        return $workspace;
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
