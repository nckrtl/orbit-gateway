<?php

declare(strict_types=1);

use App\Http\Requests\TopLevelJsonObjectInspector;

it('returns the exact decoded top-level object', function (): void {
    $payload = new TopLevelJsonObjectInspector()->inspect(
        '{"role":"app-dev","converge_existing":false}',
        ['role', 'converge_existing'],
    );

    expect($payload)->toBe([
        'role' => 'app-dev',
        'converge_existing' => false,
    ]);
});

it('treats an empty body as an empty object', function (): void {
    expect(new TopLevelJsonObjectInspector()->inspect('', ['force', 'purge_data']))
        ->toBeEmpty();
});

it('rejects malformed JSON and non-object top-level values', function (string $json): void {
    expect(fn (): array => new TopLevelJsonObjectInspector()->inspect($json, ['role']))
        ->toThrow(UnexpectedValueException::class, 'The request body must be a valid JSON object.');
})->with([
    'malformed object' => ['{"role":"app-dev"'],
    'list' => ['["app-dev"]'],
    'scalar' => ['"app-dev"'],
    'null' => ['null'],
]);

it('rejects literal and escaped duplicate top-level keys without echoing either value', function (
    string $json,
): void {
    try {
        new TopLevelJsonObjectInspector()->inspect($json, ['role']);
    } catch (UnexpectedValueException $exception) {
        expect($exception->getMessage())
            ->toBe('The request body contains duplicate top-level keys.')
            ->not->toContain('first-sentinel', 'second-sentinel');

        return;
    }

    test()->fail('Expected duplicate keys to fail validation.');
})->with([
    'literal duplicate' => ['{"role":"first-sentinel","role":"second-sentinel"}'],
    'escaped duplicate' => ['{"role":"first-sentinel","r\\u006fle":"second-sentinel"}'],
]);

it('rejects unknown top-level keys without echoing their names or values', function (): void {
    try {
        new TopLevelJsonObjectInspector()->inspect(
            '{"role":"app-dev","raw-sentinel":"secret-sentinel"}',
            ['role'],
        );
    } catch (UnexpectedValueException $exception) {
        expect($exception->getMessage())
            ->toBe('The request body contains unsupported top-level keys.')
            ->not->toContain('raw-sentinel', 'secret-sentinel');

        return;
    }

    test()->fail('Expected unknown keys to fail validation.');
});
