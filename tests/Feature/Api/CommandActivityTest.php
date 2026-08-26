<?php

declare(strict_types=1);

use App\Domain\Shared\LifecycleStatus;
use App\Models\Activity;
use App\Models\App as OrbitApp;
use App\Models\Node;
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
    $operator = Node::query()->create([
        'name' => 'operator',
        'status' => LifecycleStatus::Active,
        'public_ssh_host' => '192.0.2.2',
        'wireguard_address' => '10.44.0.2',
    ]);
    $this->markAsGateway($operator);

    $this
        ->withServerVariables(['REMOTE_ADDR' => '10.44.0.2'])
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

it('redacts secret repository query parameters before persistence and activity serialization', function (): void {
    $requestId = (string) Str::uuid();
    $repositoryUrl = 'https://example.test/repo.git?token=sentinel&branch=main';
    $redactedRepositoryUrl = 'https://example.test/repo.git?token=[REDACTED]&branch=main';
    $operator = Node::query()->create([
        'name' => 'operator',
        'status' => LifecycleStatus::Active,
        'public_ssh_host' => '192.0.2.2',
        'wireguard_address' => '10.44.0.2',
    ]);
    $this->markAsGateway($operator);

    $failure = $this
        ->withServerVariables(['REMOTE_ADDR' => '10.44.0.2'])
        ->withHeader('X-Orbit-Request-Id', $requestId)
        ->postJson('/api/v1/apps', [
            'slug' => '../invalid',
            'repository_url' => $repositoryUrl,
        ])
        ->assertUnprocessable()
        ->assertJsonPath('error.code', 'validation.failed');
    $activity = Activity::query()->where('request_id', $requestId)->sole();
    $properties = $activity->properties?->toArray() ?? [];
    $debugOutput = print_r($properties, return: true);

    expect($properties['input']['repository_url'] ?? null)
        ->toBe($redactedRepositoryUrl)
        ->and($failure->getContent())
        ->not->toContain('sentinel')->and($debugOutput)
        ->not->toContain('sentinel');

    $serialized = $this
        ->withServerVariables(['REMOTE_ADDR' => '10.44.0.2'])
        ->getJson("/api/v1/activities/{$activity->id}")
        ->assertOk()
        ->assertJsonPath('data.properties.input.repository_url', $redactedRepositoryUrl);

    expect($serialized->getContent())->not->toContain('sentinel');
});

it('records route model binding failures as http 404', function (): void {
    $requestId = (string) Str::uuid();
    $operator = Node::query()->create([
        'name' => 'operator',
        'status' => LifecycleStatus::Active,
        'public_ssh_host' => '192.0.2.2',
        'wireguard_address' => '10.44.0.2',
    ]);
    $this->markAsGateway($operator);

    $this
        ->withServerVariables(['REMOTE_ADDR' => '10.44.0.2'])
        ->withHeader('X-Orbit-Request-Id', $requestId)
        ->getJson('/api/v1/apps/999999')
        ->assertNotFound()
        ->assertJsonPath('error.code', 'http.404');

    expect(Activity::query()->where('request_id', $requestId)->sole()->error_code)->toBe('http.404');
});

it('correlates unhandled failures without exposing exception text', function (): void {
    $requestId = (string) Str::uuid();
    $secret = (string) Str::uuid();
    $operator = Node::query()->create([
        'name' => 'operator',
        'status' => LifecycleStatus::Active,
        'public_ssh_host' => '192.0.2.2',
        'wireguard_address' => '10.44.0.2',
    ]);
    $this->markAsGateway($operator);
    OrbitApp::creating(static function () use ($secret): never {
        throw new RuntimeException("Unexpected APP_KEY={$secret}");
    });

    $response = $this
        ->withServerVariables(['REMOTE_ADDR' => '10.44.0.2'])
        ->withHeader('X-Orbit-Request-Id', $requestId)
        ->postJson('/api/v1/apps', [
            'slug' => 'acme',
            'repository_url' => 'https://github.com/acme/site.git',
        ]);

    $response
        ->assertInternalServerError()
        ->assertHeader('X-Orbit-Request-Id', $requestId)
        ->assertJsonPath('error.code', 'gateway.unhandled')
        ->assertJsonPath('error.message', 'The gateway could not complete the request.');

    expect($response->getContent())
        ->not
        ->toContain($secret)
        ->and(Activity::query()->where('request_id', $requestId)->sole()->error_code)
        ->toBe('gateway.unhandled');
});

it('records node access add and remove commands against the serving node and preserves access failures', function (): void {
    $gateway = $this->markAsGateway(Node::query()->create([
        'name' => 'gateway',
        'status' => LifecycleStatus::Active,
        'public_ssh_host' => '192.0.2.2',
        'wireguard_address' => '10.44.0.2',
    ]));
    $serving = Node::query()->create([
        'name' => 'serving',
        'status' => LifecycleStatus::Active,
        'public_ssh_host' => '192.0.2.3',
        'wireguard_address' => '10.44.0.3',
    ]);
    $consumer = Node::query()->create([
        'name' => 'consumer',
        'status' => LifecycleStatus::Active,
        'public_ssh_host' => '192.0.2.4',
        'wireguard_address' => '10.44.0.4',
    ]);
    $directOnly = Node::query()->create([
        'name' => 'direct-only',
        'status' => LifecycleStatus::Active,
        'public_ssh_host' => '192.0.2.5',
        'wireguard_address' => '10.44.0.5',
    ]);
    $directOnly->accessibleNodes()->attach($serving);
    $addRequestId = (string) Str::uuid();
    $removeRequestId = (string) Str::uuid();
    $forbiddenRequestId = (string) Str::uuid();

    $this
        ->withServerVariables(['REMOTE_ADDR' => $gateway->wireguard_address])
        ->withHeader('X-Orbit-Request-Id', $addRequestId)
        ->putJson("/api/v1/nodes/{$serving->id}/access/{$consumer->id}")
        ->assertOk();

    $this
        ->withServerVariables(['REMOTE_ADDR' => $gateway->wireguard_address])
        ->withHeader('X-Orbit-Request-Id', $removeRequestId)
        ->deleteJson("/api/v1/nodes/{$serving->id}/access/{$consumer->id}")
        ->assertOk();

    $this
        ->withServerVariables(['REMOTE_ADDR' => $directOnly->wireguard_address])
        ->withHeader('X-Orbit-Request-Id', $forbiddenRequestId)
        ->putJson("/api/v1/nodes/{$serving->id}/access/{$consumer->id}")
        ->assertForbidden()
        ->assertJsonPath('error.code', 'node_access.required');

    expect(Activity::query()->where('request_id', $addRequestId)->sole())
        ->command->toBe('node:access:add')
        ->subject_type->toBe(Node::class)
        ->subject_id->toBe($serving->id)
        ->target_node_id->toBe($serving->id);

    expect(Activity::query()->where('request_id', $removeRequestId)->sole())
        ->command->toBe('node:access:remove')
        ->subject_type->toBe(Node::class)
        ->subject_id->toBe($serving->id)
        ->target_node_id->toBe($serving->id);

    expect(Activity::query()->where('request_id', $forbiddenRequestId)->sole())
        ->command->toBe('node:access:add')
        ->status->toBe('failed')
        ->error_code->toBe('node_access.required')
        ->subject_type->toBe(Node::class)
        ->subject_id->toBe($serving->id)
        ->target_node_id->toBe($serving->id);
});
