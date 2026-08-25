<?php

declare(strict_types=1);

use Illuminate\Support\Str;

describe('GET /api/v1/gateway/status', function (): void {
    it('returns gateway status with the caller request ID', function (): void {
        $requestId = (string) Str::uuid();

        $response = $this
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->getJson('/api/v1/gateway/status');

        $response
            ->assertOk()
            ->assertHeader('X-Orbit-Request-Id', $requestId)
            ->assertJsonPath('data.name', 'orbit-gateway')
            ->assertJsonPath('data.status', 'ok')
            ->assertJsonPath('data.php_version', PHP_VERSION)
            ->assertJsonPath('meta.request_id', $requestId)
            ->assertJsonStructure([
                'data' => ['name', 'status', 'version', 'php_version', 'laravel_version'],
                'meta' => ['request_id'],
            ]);
    });

    it('generates a request ID when the caller omits it', function (): void {
        $response = $this->getJson('/api/v1/gateway/status');

        $requestId = $response->headers->get('X-Orbit-Request-Id');

        expect($requestId)
            ->toBeString()
            ->and(Str::isUuid($requestId))
            ->toBeTrue();

        $response
            ->assertOk()
            ->assertJsonPath('meta.request_id', $requestId);
    });

    it('replaces an invalid caller request ID', function (): void {
        $response = $this
            ->withHeader('X-Orbit-Request-Id', 'not-a-uuid')
            ->getJson('/api/v1/gateway/status');

        $requestId = $response->headers->get('X-Orbit-Request-Id');

        expect($requestId)
            ->toBeString()
            ->not
            ->toBe('not-a-uuid')
            ->and(Str::isUuid($requestId))
            ->toBeTrue();

        $response
            ->assertOk()
            ->assertJsonPath('meta.request_id', $requestId);
    });
});
