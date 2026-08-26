<?php

declare(strict_types=1);

use App\Models\Activity;

describe('GET /api/v1/gateway/status', function (): void {
    it('returns gateway status with each supported caller request ID', function (string $requestId): void {
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

        expect(Activity::query()->sole()->request_id)->toBe($requestId);
    })->with([
        'UUID v1' => '123e4567-e89b-12d3-a456-426614174000',
        'UUID v2' => '123e4567-e89b-22d3-a456-426614174000',
        'UUID v3' => '123e4567-e89b-32d3-a456-426614174000',
        'UUID v4' => '123e4567-e89b-42d3-a456-426614174000',
        'UUID v5' => '123e4567-e89b-52d3-a456-426614174000',
        'UUID v6' => '123e4567-e89b-62d3-a456-426614174000',
        'UUID v7' => '0198e15c-bf97-7c23-8f1f-61b8fe67a844',
        'UUID v8 uppercase' => '123E4567-E89B-82D3-B456-426614174000',
    ]);

    it('generates a request ID when the caller omits it', function (): void {
        $response = $this->getJson('/api/v1/gateway/status');

        $requestId = $response->headers->get('X-Orbit-Request-Id');

        expect($requestId)
            ->toBeString()
            ->toMatch('/\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/iD');

        $response
            ->assertOk()
            ->assertJsonPath('meta.request_id', $requestId);

        expect(Activity::query()->sole()->request_id)->toBe($requestId);
    });

    it('replaces a non-RFC caller request ID with a correlated UUID v4', function (string $invalidRequestId): void {
        $response = $this
            ->withHeader('X-Orbit-Request-Id', $invalidRequestId)
            ->getJson('/api/v1/gateway/status');

        $requestId = $response->headers->get('X-Orbit-Request-Id');

        expect($requestId)
            ->toBeString()
            ->not
            ->toBe($invalidRequestId)
            ->toMatch('/\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/iD');

        $response
            ->assertOk()
            ->assertJsonPath('meta.request_id', $requestId);

        expect(Activity::query()->sole()->request_id)->toBe($requestId);
    })->with([
        'malformed' => 'not-a-uuid',
        'invalid version' => '0198e15c-bf97-0c23-8f1f-61b8fe67a844',
        'invalid variant' => '0198e15c-bf97-7c23-1f1f-61b8fe67a844',
    ]);
});
