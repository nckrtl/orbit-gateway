<?php

declare(strict_types=1);

namespace App\Infrastructure\Tools;

use App\Domain\Tools\ToolManagerName;
use App\Domain\Tools\ToolOperation;
use App\Domain\Tools\ToolOperationException;
use App\Domain\Tools\ToolOperationLock;
use App\Domain\Tools\ToolOutcome;
use Closure;
use Illuminate\Support\Facades\Cache;

final class NativeToolOperationLock implements ToolOperationLock
{
    public function run(
        int $nodeId,
        ToolManagerName $manager,
        string $package,
        ToolOperation $operation,
        ?string $versionConstraint,
        Closure $callback,
    ): mixed {
        $identity = Cache::lock(
            "orbit:tool:{$nodeId}:{$manager->value}:".hash('sha256', $package),
            3_600,
        );

        if (! $identity->get()) {
            throw $this->lockedException(
                nodeId: $nodeId,
                manager: $manager,
                package: $package,
                operation: $operation,
                versionConstraint: $versionConstraint,
                message: 'A tool mutation for this package is already active.',
            );
        }

        $managerScope = Cache::lock("orbit:tool-manager:{$nodeId}:{$manager->value}", 3_600);

        try {
            if (! $managerScope->get()) {
                throw $this->lockedException(
                    nodeId: $nodeId,
                    manager: $manager,
                    package: $package,
                    operation: $operation,
                    versionConstraint: $versionConstraint,
                    message: 'A shared tool manager mutation is already active.',
                );
            }

            try {
                return $callback();
            } finally {
                $managerScope->release();
            }
        } finally {
            $identity->release();
        }
    }

    private function lockedException(
        int $nodeId,
        ToolManagerName $manager,
        string $package,
        ToolOperation $operation,
        ?string $versionConstraint,
        string $message,
    ): ToolOperationException {
        return new ToolOperationException(
            step: $operation->value,
            errorCode: 'tool.operation_locked',
            outcome: ToolOutcome::ManagerFailed,
            status: 409,
            nodeId: $nodeId,
            manager: $manager->value,
            package: $package,
            versionConstraint: $versionConstraint,
            message: $message,
        );
    }
}
