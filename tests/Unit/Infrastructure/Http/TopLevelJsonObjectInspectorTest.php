<?php

declare(strict_types=1);

use App\Infrastructure\Http\TopLevelJsonObjectInspector;

describe(TopLevelJsonObjectInspector::class, function (): void {
    it('accepts one valid top-level object and returns canonical keys', function (): void {
        $keys = app(TopLevelJsonObjectInspector::class)->inspect(
            '{"role":"app-dev","nested":{"value":[1,true,null]}}',
            ['role', 'nested'],
        );

        expect($keys)->toBe(['role', 'nested']);
    });

    it('rejects literal and escaped duplicate top-level keys', function (string $json): void {
        expect(fn (): array => app(TopLevelJsonObjectInspector::class)->inspect($json, ['role']))
            ->toThrow(InvalidArgumentException::class);
    })->with([
        'literal' => ['{"role":"app-dev","role":"app-dev"}'],
        'escaped' => ['{"role":"app-dev","r\\u006fle":"app-dev"}'],
    ]);

    it('rejects unknown keys and malformed or non-object JSON', function (string $json): void {
        expect(fn (): array => app(TopLevelJsonObjectInspector::class)->inspect($json, ['role']))
            ->toThrow(InvalidArgumentException::class);
    })->with([
        'unknown' => ['{"role":"app-dev","sentinel":"secret"}'],
        'malformed' => ['{"role":"app-dev"'],
        'array' => ['["app-dev"]'],
        'trailing' => ['{"role":"app-dev"} false'],
    ]);
});
