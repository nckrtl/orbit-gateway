<?php

declare(strict_types=1);

namespace App\Actions\Instances;

use App\Domain\AppDev\AppDevRuntimeConverger;
use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\AppProd\AppProdRuntimeConverger;
use App\Domain\Instances\CertificateMode;
use App\Domain\Shared\LifecycleStatus;
use App\Domain\Shared\ResourceOperationException;
use App\Models\Instance;
use Throwable;

final readonly class RemoveInstanceAction
{
    public function __construct(
        private AppDevRuntimeConverger $runtime,
        private AppProdRuntimeConverger $productionRuntime,
    ) {}

    public function execute(Instance $instance): Instance
    {
        if ($instance->workspaces()->exists()) {
            throw new ResourceOperationException(
                errorCode: 'instance.has_workspaces',
                message: "Instance [{$instance->name}] still has workspaces.",
                status: 409,
            );
        }

        if ($instance->processes()->exists()) {
            throw new ResourceOperationException(
                errorCode: 'instance.has_processes',
                message: "Instance [{$instance->name}] still has processes.",
                status: 409,
            );
        }

        $instance->update(['status' => LifecycleStatus::Removing]);

        try {
            $runtime = $instance->certificate_mode === CertificateMode::Acme
                ? $this->productionRuntime
                : $this->runtime;
            $runtime->removeInstance($instance->load(['app', 'node']));
        } catch (RuntimeConvergenceException $exception) {
            $this->markFailed($instance, $exception);

            throw $exception;
        } catch (Throwable $exception) {
            $failure = new RuntimeConvergenceException(
                step: 'unknown',
                errorCode: 'instance.remove_failed',
                message: 'Instance removal failed.',
                previous: $exception,
            );
            $this->markFailed($instance, $failure);

            throw $failure;
        }

        $instance->delete();

        return $instance;
    }

    private function markFailed(Instance $instance, RuntimeConvergenceException $exception): void
    {
        $instance->update([
            'status' => LifecycleStatus::Failed,
            'failed_step' => $exception->step,
            'error_code' => $exception->errorCode,
        ]);
    }
}
