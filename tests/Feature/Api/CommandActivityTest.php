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
