<?php

declare(strict_types=1);

use App\Domain\Tools\ToolManagerException;
use App\Domain\Tools\ToolOperationException;
use App\Domain\Tools\ToolOutcome;
use App\Infrastructure\Processes\CommandResult;

describe(ToolManagerException::class, function (): void {
    it('carries stable safe tool manager failure metadata', function (): void {
        $result = new CommandResult(
            exitCode: 1,
            stdout: 'safe stdout',
            stderr: 'safe stderr',
            durationMs: 23,
            truncated: true,
        );
        $previous = new RuntimeException('Infrastructure operation failed.');
        $exception = new ToolManagerException(
            step: 'install',
            message: 'The tool manager operation failed.',
            result: $result,
            previous: $previous,
        );

        expect($exception->getMessage())
            ->toBe('The tool manager operation failed.')
            ->and($exception->step)->toBe('install')
            ->and($exception->result?->exitCode)->toBe(1)
            ->and($exception->result?->durationMs)->toBe(23)
            ->and($exception->result?->truncated)->toBeTrue()
            ->and($exception->result?->stdout)->toBeEmpty()
            ->and($exception->result?->stderr)->toBeEmpty()
            ->and($exception->getPrevious())->toBe($previous);
    });

    it('stores only safe command metadata and keeps raw output outside debug representations', function (): void {
        $stdoutSentinel = 'sentinel-stdout';
        $stderrSentinel = 'sentinel-stderr';
        $result = new CommandResult(
            exitCode: 1,
            stdout: $stdoutSentinel,
            stderr: $stderrSentinel,
            durationMs: 23,
            truncated: true,
        );
        $exception = new ToolManagerException(
            step: 'install',
            message: 'The tool manager operation failed.',
            result: $result,
        );

        $printed = print_r($exception, return: true);
        $exported = var_export($exception, return: true);
        $publicChain = print_r([
            'step' => $exception->step,
            'message' => $exception->getMessage(),
            'result' => $exception->result,
        ], return: true);

        expect($exception->result)
            ->not->toBe($result)
            ->and($printed)->toContain('The tool manager operation failed.', 'install')
            ->and($exported)->toContain('The tool manager operation failed.', 'install');

        expect(str_contains($exception->getMessage(), $stdoutSentinel))->toBeFalse()
            ->and(str_contains($exception->getMessage(), $stderrSentinel))->toBeFalse()
            ->and(str_contains($printed, $stdoutSentinel))->toBeFalse()
            ->and(str_contains($printed, $stderrSentinel))->toBeFalse()
            ->and(str_contains($exported, $stdoutSentinel))->toBeFalse()
            ->and(str_contains($exported, $stderrSentinel))->toBeFalse()
            ->and(str_contains($publicChain, $stdoutSentinel))->toBeFalse()
            ->and(str_contains($publicChain, $stderrSentinel))->toBeFalse();
    });

    it('keeps the public tool operation exception chain free from raw manager output', function (): void {
        $stdoutSentinel = 'sentinel-stdout';
        $stderrSentinel = 'sentinel-stderr';
        $managerException = new ToolManagerException(
            step: 'install',
            message: 'The tool manager operation failed.',
            result: new CommandResult(
                exitCode: 1,
                stdout: $stdoutSentinel,
                stderr: $stderrSentinel,
                durationMs: 23,
                truncated: true,
            ),
        );
        $operationException = new ToolOperationException(
            step: 'install',
            errorCode: 'tool.install_failed',
            outcome: ToolOutcome::ManagerFailed,
            status: 502,
            nodeId: 7,
            manager: 'vp',
            package: '@openai/codex',
            versionConstraint: '^0.150',
            message: 'The tool install failed.',
            previous: $managerException,
        );
        $printed = print_r($operationException, return: true);
        $exported = var_export($operationException, return: true);
        $publicChain = print_r([
            'step' => $operationException->step,
            'errorCode' => $operationException->errorCode,
            'outcome' => $operationException->outcome->value,
            'previous' => $operationException->getPrevious(),
        ], return: true);

        expect($operationException->getPrevious())->toBe($managerException)
            ->and($printed)->toContain('The tool install failed.', 'tool.install_failed')
            ->and($exported)->toContain('The tool install failed.', 'tool.install_failed');

        expect(str_contains($printed, $stdoutSentinel))->toBeFalse()
            ->and(str_contains($printed, $stderrSentinel))->toBeFalse()
            ->and(str_contains($exported, $stdoutSentinel))->toBeFalse()
            ->and(str_contains($exported, $stderrSentinel))->toBeFalse()
            ->and(str_contains($publicChain, $stdoutSentinel))->toBeFalse()
            ->and(str_contains($publicChain, $stderrSentinel))->toBeFalse();
    });
});
