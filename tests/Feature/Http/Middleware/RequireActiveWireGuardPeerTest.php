<?php

declare(strict_types=1);

use App\Domain\Instances\CertificateMode;
use App\Domain\Processes\ProcessRuntimeManager;
use App\Domain\Shared\LifecycleStatus;
use App\Http\Middleware\RequireActiveWireGuardPeer;
use App\Models\Activity;
use App\Models\App as OrbitApp;
use App\Models\Instance;
use App\Models\Node;
use App\Models\Process;
use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Str;

it('leaves only bootstrap discovery and trust commands outside active peer authentication', function (): void {
    $unprotectedCommands = collect(Route::getRoutes()->getRoutes())
        ->filter(static fn (\Illuminate\Routing\Route $route): bool => str_starts_with($route->uri(), 'api/v1/'))
        ->reject(
            static fn (\Illuminate\Routing\Route $route): bool => in_array(
                RequireActiveWireGuardPeer::class,
                $route->gatherMiddleware(),
                strict: true,
            ),
        )
        ->map(static fn (\Illuminate\Routing\Route $route): ?string => $route->getName())
        ->sort()
        ->values()
        ->all();

    expect($unprotectedCommands)->toBe(['gateway:status', 'gateway:trust']);
});

it('rejects resource state and process logs from unknown or inactive peers', function (
    ?LifecycleStatus $callerStatus,
    string $remoteAddress,
): void {
    $trusted = Node::query()->create([
        'name' => 'trusted-operator',
        'status' => LifecycleStatus::Active,
        'public_ssh_host' => '192.0.2.10',
        'wireguard_address' => '10.44.0.2',
    ]);

    if ($callerStatus instanceof LifecycleStatus) {
        Node::query()->create([
            'name' => 'inactive-operator',
            'status' => $callerStatus,
            'public_ssh_host' => '192.0.2.11',
            'wireguard_address' => $remoteAddress,
        ]);
    }

    $process = peer_boundary_process($trusted);
    $runtime = new PeerBoundaryFakeProcessRuntimeManager;
    app()->instance(ProcessRuntimeManager::class, $runtime);
    $stateRequestId = (string) Str::uuid();
    $logsRequestId = (string) Str::uuid();
    $spoofedHeaders = [
        'Forwarded' => 'for=10.44.0.2',
        'X-Forwarded-For' => '10.44.0.2',
        'X-Real-IP' => '10.44.0.2',
        'X-Orbit-WireGuard-Ip' => '10.44.0.2',
    ];
    TrustProxies::at('*');

    try {
        $stateResponse = $this
            ->withServerVariables(['REMOTE_ADDR' => $remoteAddress])
            ->withHeaders([...$spoofedHeaders, 'X-Orbit-Request-Id' => $stateRequestId])
            ->getJson('/api/v1/apps');
        $logsResponse = $this
            ->withServerVariables(['REMOTE_ADDR' => $remoteAddress])
            ->withHeaders([...$spoofedHeaders, 'X-Orbit-Request-Id' => $logsRequestId])
            ->getJson("/api/v1/processes/{$process->id}/logs?lines=25");
    } finally {
        TrustProxies::flushState();
    }

    $stateResponse
        ->assertForbidden()
        ->assertJsonPath('error.code', 'peer.identity_unknown')
        ->assertJsonMissing(['private-app']);
    $logsResponse
        ->assertForbidden()
        ->assertJsonPath('error.code', 'peer.identity_unknown')
        ->assertJsonMissing(['sentinel-private-log']);

    foreach ([$stateRequestId, $logsRequestId] as $requestId) {
        $activity = Activity::query()->where('request_id', $requestId)->sole();

        expect($activity->caller_ip)
            ->toBe($remoteAddress)
            ->and($activity->caller_node_id)
            ->toBeNull()
            ->and($activity->error_code)
            ->toBe('peer.identity_unknown');
    }

    expect($runtime->logCalls)->toBe(0);
})->with([
    'unknown peer' => [null, '10.44.0.99'],
    'inactive registered peer' => [LifecycleStatus::Failed, '10.44.0.98'],
]);

it('identifies the peer before resolving a route-bound resource', function (string $path): void {
    $requestId = (string) Str::uuid();

    $this
        ->withServerVariables(['REMOTE_ADDR' => '10.44.0.99'])
        ->withHeader('X-Orbit-Request-Id', $requestId)
        ->getJson($path)
        ->assertForbidden()
        ->assertJsonPath('error.code', 'peer.identity_unknown');

    $activity = Activity::query()->where('request_id', $requestId)->sole();

    expect($activity->caller_node_id)
        ->toBeNull()
        ->and($activity->caller_ip)
        ->toBe('10.44.0.99')
        ->and($activity->error_code)
        ->toBe('peer.identity_unknown');
})->with([
    'node' => '/api/v1/nodes/999999',
    'node firewall rules' => '/api/v1/nodes/999999/firewall-rules',
    'app' => '/api/v1/apps/999999',
    'instance' => '/api/v1/instances/999999',
    'workspace' => '/api/v1/workspaces/999999',
    'process logs' => '/api/v1/processes/999999/logs',
    'activity' => '/api/v1/activities/999999',
]);

it('allows an active role-less operator to read resource state and process logs', function (): void {
    $operator = Node::query()->create([
        'name' => 'roleless-operator',
        'status' => LifecycleStatus::Active,
        'public_ssh_host' => '192.0.2.10',
        'wireguard_address' => '10.44.0.2',
    ]);
    $process = peer_boundary_process($operator);
    $runtime = new PeerBoundaryFakeProcessRuntimeManager;
    app()->instance(ProcessRuntimeManager::class, $runtime);
    $stateRequestId = (string) Str::uuid();
    $logsRequestId = (string) Str::uuid();

    $this
        ->withServerVariables(['REMOTE_ADDR' => $operator->wireguard_address])
        ->withHeader('X-Orbit-Request-Id', $stateRequestId)
        ->getJson('/api/v1/apps')
        ->assertOk()
        ->assertJsonPath('data.0.slug', 'private-app');
    $this
        ->withServerVariables(['REMOTE_ADDR' => $operator->wireguard_address])
        ->withHeader('X-Orbit-Request-Id', $logsRequestId)
        ->getJson("/api/v1/processes/{$process->id}/logs?lines=25")
        ->assertOk()
        ->assertJsonPath('data.logs', 'sentinel-private-log');

    foreach ([$stateRequestId, $logsRequestId] as $requestId) {
        $activity = Activity::query()->where('request_id', $requestId)->sole();

        expect($activity->caller_ip)
            ->toBe($operator->wireguard_address)
            ->and($activity->caller_node_id)
            ->toBe($operator->id);
    }

    expect($operator->roles()->count())
        ->toBe(0)
        ->and($runtime->logCalls)
        ->toBe(1);
});

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

function peer_boundary_process(Node $node): Process
{
    $app = OrbitApp::query()->create([
        'name' => 'Private App',
        'slug' => 'private-app',
        'repository_url' => 'https://example.test/private.git',
    ]);
    $instance = Instance::query()->create([
        'app_id' => $app->id,
        'node_id' => $node->id,
        'name' => 'main',
        'environment' => 'development',
        'checkout_path' => '/home/orbit/apps/private-app',
        'document_root' => 'public',
        'php_version' => '8.5',
        'hostname' => 'private-app.example.test',
        'certificate_mode' => CertificateMode::OrbitCa,
        'status' => LifecycleStatus::Active,
    ]);

    return Process::query()->create([
        'owner_type' => Instance::class,
        'owner_id' => $instance->id,
        'name' => 'private-worker',
        'runtime' => 'systemd',
        'working_directory' => $instance->checkout_path,
        'runtime_config' => ['command' => ['/usr/bin/php', 'artisan', 'queue:work']],
        'restart_policy' => 'always',
        'desired_state' => 'running',
        'status' => LifecycleStatus::Active,
    ]);
}

/** @mago-expect lint:file-name The fake belongs to the peer middleware API scenarios. */
final class PeerBoundaryFakeProcessRuntimeManager implements ProcessRuntimeManager
{
    public int $logCalls = 0;

    public function converge(Process $process): void {}

    public function start(Process $process): void {}

    public function stop(Process $process): void {}

    public function restart(Process $process): void {}

    public function remove(Process $process): void {}

    public function status(Process $process): string
    {
        return 'running';
    }

    public function logs(Process $process, int $lines): string
    {
        $this->logCalls++;

        return 'sentinel-private-log';
    }
}
