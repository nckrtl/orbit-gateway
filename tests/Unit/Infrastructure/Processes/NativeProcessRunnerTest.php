<?php

declare(strict_types=1);

use App\Infrastructure\Processes\NativeProcessRunner;
use App\Infrastructure\Processes\ProcessInvocation;

it('captures bounded command output and exit state', function (): void {
    $runner = new NativeProcessRunner(maxOutputBytes: 8);

    $result = $runner->run(
        new ProcessInvocation(
            [
                PHP_BINARY,
                '-r',
                'fwrite(STDOUT, "123456789"); fwrite(STDERR, "abcdefghi"); exit(7);',
            ],
            timeout: 5.0,
        ),
    );

    expect($result->exitCode)
        ->toBe(7)
        ->and($result->stdout)
        ->toBe('23456789')
        ->and($result->stderr)
        ->toBe('bcdefghi')
        ->and($result->truncated)
        ->toBeTrue()
        ->and($result->durationMs)
        ->toBeGreaterThanOrEqual(0);
});
