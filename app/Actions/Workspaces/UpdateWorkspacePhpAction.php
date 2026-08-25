<?php

declare(strict_types=1);

namespace App\Actions\Workspaces;

use App\Domain\AppDev\AppDevRuntimeConverger;
use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\Shared\LifecycleStatus;
use App\Models\Workspace;
use Throwable;

final readonly class UpdateWorkspacePhpAction
{
    public function __construct(
        private AppDevRuntimeConverger $runtime,
    ) {}

    public function execute(Workspace $workspace, string $phpVersion): Workspace
    {
        $workspace->update([
            'php_version' => $phpVersion,
            'status' => LifecycleStatus::Provisioning,
            'failed_step' => null,
            'error_code' => null,
        ]);

        try {
            $this->runtime->convergeWorkspace($workspace->refresh()->load('instance.node'));
        } catch (RuntimeConvergenceException $exception) {
            $this->markFailed($workspace, $exception);

            throw $exception;
        } catch (Throwable $exception) {
            $failure = new RuntimeConvergenceException(
                step: 'unknown',
                errorCode: 'workspace.php_change_failed',
                message: 'Workspace PHP change failed.',
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

        return $workspace->refresh()->load('instance');
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
