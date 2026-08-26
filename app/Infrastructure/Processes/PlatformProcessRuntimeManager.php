<?php

declare(strict_types=1);

namespace App\Infrastructure\Processes;

use App\Domain\Processes\ProcessOperationException;
use App\Domain\Processes\ProcessRuntime;
use App\Domain\Processes\ProcessRuntimeManager;
use App\Domain\Processes\ProcessTargetResolver;
use App\Models\Process;
use SensitiveParameter;

final readonly class PlatformProcessRuntimeManager implements ProcessRuntimeManager
{
    public function __construct(
        private ProcessTargetResolver $targets,
        private ProcessRuntimeManager $linux,
        private ProcessRuntimeManager $darwin,
    ) {}

    public function converge(#[SensitiveParameter] Process $process): void
    {
        $this->manager($process)->converge($process);
    }

    public function start(#[SensitiveParameter] Process $process): void
    {
        $this->manager($process)->start($process);
    }

    public function stop(#[SensitiveParameter] Process $process): void
    {
        $this->manager($process)->stop($process);
    }

    public function restart(#[SensitiveParameter] Process $process): void
    {
        $this->manager($process)->restart($process);
    }

    public function remove(#[SensitiveParameter] Process $process): void
    {
        $this->manager($process)->remove($process);
    }

    public function status(#[SensitiveParameter] Process $process): string
    {
        return $this->manager($process)->status($process);
    }

    public function logs(#[SensitiveParameter] Process $process, int $lines): string
    {
        return $this->manager($process)->logs($process, $lines);
    }

    private function manager(#[SensitiveParameter] Process $process): ProcessRuntimeManager
    {
        $platform = $this->targets->forProcess($process)->node->platform;

        if ($platform === 'linux') {
            if ($process->runtime === ProcessRuntime::Launchd) {
                throw new ProcessOperationException(
                    step: 'select-runtime',
                    errorCode: 'process.runtime_unsupported',
                    message: 'The selected runtime is not supported on this node platform.',
                );
            }

            return $this->linux;
        }

        if ($platform === 'darwin') {
            return match ($process->runtime) {
                ProcessRuntime::Launchd => $this->darwin,
                ProcessRuntime::Docker => throw new ProcessOperationException(
                    step: 'select-runtime',
                    errorCode: 'process.runtime_unavailable',
                    message: 'The selected runtime is not available on this node platform yet.',
                ),
                ProcessRuntime::Systemd => throw new ProcessOperationException(
                    step: 'select-runtime',
                    errorCode: 'process.runtime_unsupported',
                    message: 'The selected runtime is not supported on this node platform.',
                ),
            };
        }

        throw new ProcessOperationException(
            step: 'select-runtime',
            errorCode: 'process.platform_unsupported',
            message: 'The selected node platform does not support process runtimes.',
        );
    }
}
