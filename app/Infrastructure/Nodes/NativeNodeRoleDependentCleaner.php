<?php

declare(strict_types=1);

namespace App\Infrastructure\Nodes;

use App\Domain\AppDev\AppDevRuntimeConverger;
use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\AppProd\AppProdRuntimeConverger;
use App\Domain\Instances\CertificateMode;
use App\Domain\Nodes\NodeRoleDependencySet;
use App\Domain\Nodes\NodeRoleDependentCleaner;
use App\Domain\Nodes\NodeRoleOperationException;
use App\Domain\Processes\ProcessOperationException;
use App\Domain\Processes\ProcessRuntimeManager;
use App\Domain\Shared\LifecycleStatus;
use App\Infrastructure\Processes\CommandResult;
use App\Models\Instance;
use App\Models\Process;
use App\Models\Workspace;
use Throwable;

final readonly class NativeNodeRoleDependentCleaner implements NodeRoleDependentCleaner
{
    public function __construct(
        private ProcessRuntimeManager $processes,
        private AppDevRuntimeConverger $appDev,
        private AppProdRuntimeConverger $appProd,
    ) {}

    public function clean(NodeRoleDependencySet $dependencies): void
    {
        foreach ($dependencies->processIds as $processId) {
            $process = Process::query()->findOrFail($processId);

            try {
                $this->processes->remove($process);
            } catch (ProcessOperationException $exception) {
                $this->markFailed($process, $exception->step, $exception->errorCode);
                $this->fail('process-runtime', $exception->errorCode, $exception, $exception->result);
            } catch (Throwable $exception) {
                $this->markFailed($process, 'unknown', 'process.remove_failed');
                $this->fail('process-runtime', 'process.remove_failed', $exception, null);
            }
        }

        foreach ($dependencies->workspaceIds as $workspaceId) {
            $workspace = Workspace::query()->with(['instance.node'])->findOrFail($workspaceId);

            try {
                $this->appDev->unpublishWorkspace($workspace);
            } catch (RuntimeConvergenceException $exception) {
                $this->markFailed($workspace, $exception->step, $exception->errorCode);
                $this->fail('workspace-runtime', $exception->errorCode, $exception, $exception->result);
            } catch (Throwable $exception) {
                $this->markFailed($workspace, 'unknown', 'workspace.remove_failed');
                $this->fail('workspace-runtime', 'workspace.remove_failed', $exception, null);
            }
        }

        foreach ($dependencies->instanceIds as $instanceId) {
            $instance = Instance::query()->with('node')->findOrFail($instanceId);

            try {
                match ($instance->certificate_mode) {
                    CertificateMode::OrbitCa => $this->appDev->unpublishInstance($instance),
                    CertificateMode::Acme => $this->appProd->unpublishInstance($instance),
                };
            } catch (RuntimeConvergenceException $exception) {
                $this->markFailed($instance, $exception->step, $exception->errorCode);
                $this->fail('instance-runtime', $exception->errorCode, $exception, $exception->result);
            } catch (Throwable $exception) {
                $this->markFailed($instance, 'unknown', 'instance.remove_failed');
                $this->fail('instance-runtime', 'instance.remove_failed', $exception, null);
            }
        }
    }

    private function markFailed(Process|Workspace|Instance $dependent, string $step, string $errorCode): void
    {
        $dependent->update([
            'status' => LifecycleStatus::Failed,
            'failed_step' => $step,
            'error_code' => $errorCode,
        ]);
    }

    private function fail(
        string $step,
        string $underlyingErrorCode,
        Throwable $previous,
        ?CommandResult $result,
    ): never {
        throw new NodeRoleOperationException(
            step: $step,
            errorCode: 'node_role.remove_failed',
            underlyingErrorCode: $underlyingErrorCode,
            message: "Node role dependent cleanup failed at [{$step}].",
            result: $result,
            previous: $previous,
        );
    }
}
