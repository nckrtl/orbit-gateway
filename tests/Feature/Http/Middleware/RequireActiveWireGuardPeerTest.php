<?php

declare(strict_types=1);

use App\Domain\Shared\LifecycleStatus;
use App\Models\Activity;
use App\Models\Node;
use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Support\Str;

it('rejects mutating commands from an unknown peer with the correlated error', function (): void {
    $requestId = (string) Str::uuid();
    Node::query()->create([
        'name' => 'operator',
        'status' => LifecycleStatus::Active,
        'public_ssh_host' => '192.0.2.10',
        'wireguard_address' => '10.44.0.2',
    ]);
    TrustProxies::at('*');

    try {
        $response = $this
            ->withServerVariables(['REMOTE_ADDR' => '10.44.0.99'])
            ->withHeaders([
                'Forwarded' => 'for=10.44.0.2',
                'X-Forwarded-For' => '10.44.0.2',
                'X-Real-IP' => '10.44.0.2',
                'X-Orbit-Request-Id' => $requestId,
                'X-Orbit-WireGuard-Ip' => '10.44.0.2',
            ])
            ->postJson('/api/v1/apps', [
                'slug' => 'acme',
                'repository_url' => 'https://github.com/acme/site.git',
            ]);
    } finally {
        TrustProxies::flushState();
    }

    $response
        ->assertForbidden()
        ->assertHeader('X-Orbit-Request-Id', $requestId)
        ->assertJsonPath('error.code', 'peer.identity_unknown');

    $activity = Activity::query()->where('request_id', $requestId)->sole();

    expect($activity->error_code)
        ->toBe('peer.identity_unknown')
        ->and($activity->caller_ip)
        ->toBe('10.44.0.99')
        ->and($activity->caller_node_id)
        ->toBeNull();
});

it('rejects mutating commands from an inactive registered peer', function (): void {
    Node::query()->create([
        'name' => 'operator',
        'status' => LifecycleStatus::Failed,
        'public_ssh_host' => '192.0.2.10',
        'wireguard_address' => '10.44.0.2',
    ]);

    $this
        ->withServerVariables(['REMOTE_ADDR' => '10.44.0.2'])
        ->postJson('/api/v1/apps', [
            'slug' => 'acme',
            'repository_url' => 'https://github.com/acme/site.git',
        ])
        ->assertForbidden()
        ->assertJsonPath('error.code', 'peer.identity_unknown');
});

it('accepts mutating commands from an active registered peer', function (): void {
    Node::query()->create([
        'name' => 'operator',
        'status' => LifecycleStatus::Active,
        'public_ssh_host' => '192.0.2.10',
        'wireguard_address' => '10.44.0.2',
    ]);

    $this
        ->withServerVariables(['REMOTE_ADDR' => '10.44.0.2'])
        ->postJson('/api/v1/apps', [
            'slug' => 'acme',
            'repository_url' => 'https://github.com/acme/site.git',
        ])
        ->assertCreated();
});

it('keeps read-only gateway status available before peer enrollment', function (): void {
    $this
        ->withServerVariables(['REMOTE_ADDR' => '192.0.2.99'])
        ->getJson('/api/v1/gateway/status')
        ->assertOk();
});
