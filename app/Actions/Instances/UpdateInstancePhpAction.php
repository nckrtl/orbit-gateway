<?php

declare(strict_types=1);

namespace App\Actions\Instances;

use App\Domain\AppDev\AppDevRuntimeConverger;
use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\Shared\LifecycleStatus;
use App\Models\Instance;
use Throwable;

final readonly class UpdateInstancePhpAction
{
    public function __construct(
        private AppDevRuntimeConverger $runtime,
    ) {}

    public function execute(Instance $instance, string $phpVersion): Instance
    {
        $instance->update([
            'php_version' => $phpVersion,
            'status' => LifecycleStatus::Provisioning,
            'failed_step' => null,
            'error_code' => null,
        ]);

        try {
            $this->runtime->convergeInstance($instance->refresh()->load(['app', 'node']));
        } catch (RuntimeConvergenceException $exception) {
            $this->markFailed($instance, $exception);

            throw $exception;
        } catch (Throwable $exception) {
            $failure = new RuntimeConvergenceException(
                step: 'unknown',
                errorCode: 'instance.php_change_failed',
                message: 'Instance PHP change failed.',
                previous: $exception,
            );
            $this->markFailed($instance, $failure);

            throw $failure;
        }

        $instance->update([
            'status' => LifecycleStatus::Active,
            'failed_step' => null,
            'error_code' => null,
        ]);

        return $instance->refresh();
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
