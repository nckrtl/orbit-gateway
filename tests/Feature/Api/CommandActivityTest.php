<?php

declare(strict_types=1);

use App\Models\Activity;
use Illuminate\Support\Str;

it('records one completed activity for each API command', function (): void {
    $requestId = (string) Str::uuid();

    $this
        ->withHeader('X-Orbit-Request-Id', $requestId)
        ->getJson('/api/v1/gateway/status')
        ->assertOk();

    $activity = Activity::query()->sole();

    expect($activity->request_id)
        ->toBe($requestId)
        ->and($activity->command)
        ->toBe('gateway:status')
        ->and($activity->status)
        ->toBe('succeeded')
        ->and($activity->caller_ip)
        ->toBe('127.0.0.1')
        ->and($activity->duration_ms)
        ->toBeGreaterThanOrEqual(0);
});

it('recursively redacts sensitive input and URL userinfo before persistence', function (): void {
    $requestId = (string) Str::uuid();
    $repositoryPassword = (string) Str::uuid();
    $nestedToken = (string) Str::uuid();
    $nestedPassword = (string) Str::uuid();

    $this
        ->withHeader('X-Orbit-Request-Id', $requestId)
        ->postJson('/api/v1/apps', [
            'slug' => 'secret-app',
            'repository_url' => "https://alice:{$repositoryPassword}@example.com/acme/site.git",
            'defaults' => [
                'services' => [
                    ['name' => 'github', 'token' => $nestedToken],
                ],
                'database' => ['password' => $nestedPassword],
            ],
        ])
        ->assertUnprocessable()
        ->assertJsonPath('error.code', 'validation.failed');

    $input = Activity::query()->where('request_id', $requestId)->sole()->properties?->get('input');

    expect($input)
        ->toBeArray()
        ->and($input['repository_url'] ?? null)
        ->toBe('https://[REDACTED]@example.com/acme/site.git')
        ->and($input['defaults']['services'][0]['token'] ?? null)
        ->toBe('[REDACTED]')
        ->and($input['defaults']['database']['password'] ?? null)
        ->toBe('[REDACTED]')
        ->and(json_encode($input))
        ->not->toContain($repositoryPassword, $nestedToken, $nestedPassword);
});

it('records route model binding failures as http 404', function (): void {
    $requestId = (string) Str::uuid();

    $this
        ->withHeader('X-Orbit-Request-Id', $requestId)
        ->getJson('/api/v1/apps/999999')
        ->assertNotFound()
        ->assertJsonPath('error.code', 'http.404');

    expect(Activity::query()->where('request_id', $requestId)->sole()->error_code)->toBe('http.404');
});
