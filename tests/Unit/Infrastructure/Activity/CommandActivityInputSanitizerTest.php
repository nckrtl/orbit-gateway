<?php

declare(strict_types=1);

use App\Infrastructure\Activity\CommandActivityInputSanitizer;
use Illuminate\Support\Str;

it('redacts nested structured secret keys without matching ordinary siblings', function (): void {
    $sanitizer = new CommandActivityInputSanitizer;
    $secret = (string) Str::uuid();
    $redacted = '[REDACTED]';
    $active = 'active';

    expect($sanitizer->sanitize([
        'APP_KEY' => $secret,
        'application-key' => $secret,
        'api_key' => $secret,
        'api-token' => $secret,
        'access_token' => $secret,
        'refresh-token' => $secret,
        'password_hash' => $secret,
        'private_key' => $secret,
        'pre_shared_key' => $secret,
        'nested' => ['user_password' => $secret],
        'public_key' => 'peer-public',
        'token_count' => 3,
        'secretary' => $active,
    ]))->toBe([
        'APP_KEY' => $redacted,
        'application-key' => $redacted,
        'api_key' => $redacted,
        'api-token' => $redacted,
        'access_token' => $redacted,
        'refresh-token' => $redacted,
        'password_hash' => $redacted,
        'private_key' => $redacted,
        'pre_shared_key' => $redacted,
        'nested' => ['user_password' => $redacted],
        'public_key' => 'peer-public',
        'token_count' => 3,
        'secretary' => $active,
    ]);
});

it('redacts secret assignments and authorization credentials from text', function (): void {
    $sanitizer = new CommandActivityInputSanitizer;
    $secret = (string) Str::uuid();
    $bearer = 'eyJ'.Str::random(48);

    expect($sanitizer->redactText("APP_KEY={$secret}"))
        ->toBe('APP_KEY=[REDACTED]')
        ->and($sanitizer->redactText("api-token='{$secret}'"))
        ->toBe('api-token=[REDACTED]')
        ->and($sanitizer->redactText("access_token: {$secret}"))
        ->toBe('access_token: [REDACTED]')
        ->and($sanitizer->redactText('{"refresh-token":"'.$secret.'"}'))
        ->toBe('{"refresh-token":"[REDACTED]"}')
        ->and($sanitizer->redactText("Authorization: Bearer {$bearer}"))
        ->toBe('Authorization: [REDACTED]')
        ->and($sanitizer->redactText('Proxy-Authorization: Basic dXNlcjpwYXNz'))
        ->toBe('Proxy-Authorization: [REDACTED]')
        ->and($sanitizer->redactText("used Bearer {$bearer} then continued"))
        ->toBe('used Bearer [REDACTED] then continued')
        ->and($sanitizer->redactText("https://alice:{$secret}@example.com/repository.git"))
        ->toBe('https://[REDACTED]@example.com/repository.git')
        ->and($sanitizer->redactText('secretary=active token_count=3 status=ok'))
        ->toBe('secretary=active token_count=3 status=ok');
});

it('redacts only recognized secret query parameters in arbitrary text', function (
    string $url,
    string $expectedUrl,
): void {
    $sanitizer = new CommandActivityInputSanitizer;
    $sanitized = $sanitizer->sanitize([
        'url' => $url,
        'message' => "Clone failed for {$url}",
        'error' => "Could not fetch {$url}",
    ]);
    $debugOutput = print_r($sanitized, return: true);

    expect($sanitized)
        ->toBe([
            'url' => $expectedUrl,
            'message' => "Clone failed for {$expectedUrl}",
            'error' => "Could not fetch {$expectedUrl}",
        ])
        ->and($debugOutput)
        ->not
        ->toContain('sentinel')
        ->and($sanitizer->redactText('https://example.test/repo.git?branch=main&token_count=3'))
        ->toBe('https://example.test/repo.git?branch=main&token_count=3');
})->with([
    'token' => [
        'https://example.test/repo.git?token=sentinel&branch=main',
        'https://example.test/repo.git?token=[REDACTED]&branch=main',
    ],
    'api key' => [
        'error: https://example.test/repo.git?api_key=sentinel&branch=main',
        'error: https://example.test/repo.git?api_key=[REDACTED]&branch=main',
    ],
    'access token' => [
        'https://example.test/repo.git?branch=main&access_token=sentinel&depth=1',
        'https://example.test/repo.git?branch=main&access_token=[REDACTED]&depth=1',
    ],
]);

it('redacts complete PEM blocks without storing private material', function (): void {
    $sanitizer = new CommandActivityInputSanitizer;
    $label = 'PRIVATE KEY';
    $body = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj';
    $pem = '-----BEGIN '.$label."-----\n{$body}\n-----END {$label}-----";

    expect($sanitizer->redactText("peer material:\n{$pem}\nstatus=ok"))
        ->toBe("peer material:\n[REDACTED]\nstatus=ok")
        ->not
        ->toContain($body)
        ->and($sanitizer->redactText('The BEGIN of the ceremony was delayed until END of day'))
        ->toBe('The BEGIN of the ceremony was delayed until END of day');
});

it('redacts every value in process environment maps regardless of variable name', function (): void {
    $sanitizer = new CommandActivityInputSanitizer;

    expect($sanitizer->sanitize([
        'runtime_config' => [
            'environment' => [
                'APP_ENV' => 'production',
                'DATABASE_URL' => 'postgres://operator:secret@example.test/orbit',
                'CUSTOM_NAME' => 'private-value',
            ],
        ],
        'environment' => 'production',
    ]))->toBe([
        'runtime_config' => [
            'environment' => [
                'APP_ENV' => '[REDACTED]',
                'DATABASE_URL' => '[REDACTED]',
                'CUSTOM_NAME' => '[REDACTED]',
            ],
        ],
        'environment' => 'production',
    ]);
});

it('replaces invalid process environment names while retaining valid names', function (): void {
    $sanitizer = new CommandActivityInputSanitizer;
    $sentinel = 'sentinel-invalid-environment-key';
    $sanitized = $sanitizer->sanitize([
        'environment' => [
            'APP_ENV' => 'production',
            "BAD\n{$sentinel}" => 'private-value',
            0 => 'numeric-value',
        ],
    ]);
    $debugOutput = print_r($sanitized, return: true);

    expect($sanitized)
        ->toBe([
            'environment' => [
                'APP_ENV' => '[REDACTED]',
                '[INVALID_ENVIRONMENT_NAME]' => '[REDACTED]',
            ],
        ])
        ->and($debugOutput)
        ->not->toContain($sentinel)
        ->not->toContain('private-value')
        ->not->toContain('numeric-value');
});
