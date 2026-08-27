<?php

declare(strict_types=1);

use App\Domain\Nodes\NodeRoleOperationException;
use App\Domain\Nodes\NodeRoleValidationException;
use App\Infrastructure\Processes\CommandResult;

it('carries safe node role validation details', function (): void {
    expect(class_exists(NodeRoleValidationException::class))->toBeTrue();

    $exception = new NodeRoleValidationException(
        message: 'The node role cannot be changed.',
        details: ['role' => ['The role is protected.']],
    );

    expect($exception->getMessage())
        ->toBe('The node role cannot be changed.')
        ->and($exception->details)
        ->toBe(['role' => ['The role is protected.']]);
});

it('carries stable node role operation failure metadata', function (): void {
    expect(class_exists(NodeRoleOperationException::class))->toBeTrue();

    $result = new CommandResult(
        exitCode: 1,
        stdout: 'safe stdout',
        stderr: 'safe stderr',
        durationMs: 12,
        truncated: false,
    );
    $previous = new RuntimeException('Infrastructure operation failed.');
    $exception = new NodeRoleOperationException(
        errorCode: 'node_role.convergence_failed',
        step: 'converge:firewall',
        underlyingErrorCode: 'firewall.convergence_failed',
        message: 'The node role could not converge.',
        result: $result,
        previous: $previous,
    );

    expect($exception->getMessage())
        ->toBe('The node role could not converge.')
        ->and($exception->errorCode)
        ->toBe('node_role.convergence_failed')
        ->and($exception->step)
        ->toBe('converge:firewall')
        ->and($exception->underlyingErrorCode)
        ->toBe('firewall.convergence_failed')
        ->and($exception->result?->exitCode)
        ->toBe(1)
        ->and($exception->result?->durationMs)
        ->toBe(12)
        ->and($exception->result?->truncated)
        ->toBeFalse()
        ->and($exception->result?->stdout)
        ->toBeEmpty()
        ->and($exception->result?->stderr)
        ->toBeEmpty()
        ->and($exception->getPrevious())
        ->toBe($previous);
});

it('stores only safe command metadata and keeps raw output outside debug representations', function (): void {
    $result = new CommandResult(
        exitCode: 1,
        stdout: 'sentinel-stdout',
        stderr: 'sentinel-stderr',
        durationMs: 12,
        truncated: false,
    );
    $exception = new NodeRoleOperationException(
        errorCode: 'node_role.remove_failed',
        step: 'remove:process',
        underlyingErrorCode: 'process.remove_failed',
        message: 'The node role could not be removed.',
        result: $result,
    );

    $printDebugOutput = print_r($exception, return: true);
    $exportDebugOutput = var_export($exception, return: true);

    expect($exception->result)
        ->not
        ->toBe($result)
        ->and($exception->result?->exitCode)
        ->toBe(1)
        ->and($exception->result?->durationMs)
        ->toBe(12)
        ->and($exception->result?->truncated)
        ->toBeFalse()
        ->and($exception->result?->stdout)
        ->toBeEmpty()
        ->and($exception->result?->stderr)
        ->toBeEmpty();

    expect($printDebugOutput, $exportDebugOutput)
        ->toContain(
            'The node role could not be removed.',
            'node_role.remove_failed',
            'remove:process',
            'process.remove_failed',
        )
        ->not->toContain(
            'sentinel-stdout',
            'sentinel-stderr',
            'stdout',
            'stderr',
        );
});
