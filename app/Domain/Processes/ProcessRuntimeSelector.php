<?php

declare(strict_types=1);

namespace App\Domain\Processes;

use App\Domain\Shared\ResourceOperationException;

final readonly class ProcessRuntimeSelector
{
    public function select(?ProcessRuntime $requestedRuntime, string $platform): ProcessRuntime
    {
        if ($requestedRuntime === null) {
            return match ($platform) {
                'linux' => ProcessRuntime::Systemd,
                'darwin' => ProcessRuntime::Launchd,
                default => throw new ResourceOperationException(
                    errorCode: 'process.platform_unsupported',
                    message: "Processes are not supported on [{$platform}] nodes.",
                ),
            };
        }

        if ($platform === 'linux') {
            if ($requestedRuntime === ProcessRuntime::Launchd) {
                throw new ResourceOperationException(
                    errorCode: 'process.runtime_unsupported',
                    message: 'The selected runtime is not supported on this node platform.',
                );
            }

            return $requestedRuntime;
        }

        if ($platform === 'darwin') {
            return match ($requestedRuntime) {
                ProcessRuntime::Launchd => $requestedRuntime,
                ProcessRuntime::Docker => throw new ResourceOperationException(
                    errorCode: 'process.runtime_unavailable',
                    message: 'The selected runtime is not available on this node platform yet.',
                    status: 502,
                ),
                ProcessRuntime::Systemd => throw new ResourceOperationException(
                    errorCode: 'process.runtime_unsupported',
                    message: 'The selected runtime is not supported on this node platform.',
                ),
            };
        }

        throw new ResourceOperationException(
            errorCode: 'process.platform_unsupported',
            message: "Processes are not supported on [{$platform}] nodes.",
        );
    }
}
