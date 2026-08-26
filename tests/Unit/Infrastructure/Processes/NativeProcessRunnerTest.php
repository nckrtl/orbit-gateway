<?php

declare(strict_types=1);

use App\Infrastructure\Processes\NativeProcessRunner;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Processes\ProtectedInput;

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

it('streams protected input and removes its local file after the process exits', function (): void {
    $sensitiveValue = 'ALPHA=opaque-value';
    $input = ProtectedInput::fromString($sensitiveValue);
    $streamMetadata = stream_get_meta_data($input->stream());
    $path = $streamMetadata['uri'];
    $invocation = new ProcessInvocation(
        [PHP_BINARY, '-r', 'echo hash("sha256", stream_get_contents(STDIN));'],
        timeout: 5.0,
        protectedInput: $input,
    );

    expect($invocation->input)
        ->toBeNull()
        ->and($invocation->protectedInput)
        ->toBeInstanceOf(ProtectedInput::class);

    $result = new NativeProcessRunner()->run($invocation);

    expect($result->succeeded())
        ->toBeTrue()
        ->and($result->stdout)
        ->toBe(hash('sha256', $sensitiveValue))
        ->and(is_string($path))
        ->toBeTrue()
        ->and(file_exists((string) $path))
        ->toBeFalse();
});
