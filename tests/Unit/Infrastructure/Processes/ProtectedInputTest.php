<?php

declare(strict_types=1);

use App\Infrastructure\Processes\ProtectedInput;

it('stores sensitive input in a protected temporary file without exposing it in debug output', function (): void {
    $sensitiveValue = 'ALPHA=opaque-value-with-spaces';
    $input = ProtectedInput::fromString($sensitiveValue);
    $stream = $input->stream();
    $metadata = stream_get_meta_data($stream);
    $statistics = fstat($stream);
    $debugOutput = json_encode($input->__debugInfo(), JSON_THROW_ON_ERROR);

    expect($statistics)
        ->toBeArray()
        ->and($statistics['mode'] & 0o777)
        ->toBe(0o600)
        ->and(stream_get_contents($stream))
        ->toBe($sensitiveValue)
        ->and($debugOutput)
        ->not
        ->toContain($sensitiveValue)
        ->toContain('[PROTECTED]');

    $path = $metadata['uri'];
    $input->close();

    expect($path)
        ->toBeString()
        ->and(file_exists($path))
        ->toBeFalse();
});
