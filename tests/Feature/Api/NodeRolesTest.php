<?php

declare(strict_types=1);

use App\Domain\AppDev\PrivateDnsManager;
use App\Domain\Nodes\NodeConverger;
use App\Domain\Nodes\NodeProjectionOperationLock;
use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Domain\WireGuard\GatewayPeerProjectionManager;
use App\Models\Activity;
use App\Models\Node;
use Illuminate\Support\Str;

/** @mago-expect lint:halstead Role route scenarios share the same caller and projection fakes. */
describe('POST /api/v1/nodes/{node}/roles', function (): void {
    beforeEach(function (): void {
        app()->instance(PrivateDnsManager::class, new class implements PrivateDnsManager {
            public function converge(?Node $pendingNode = null): void {}
        });
        app()->instance(NodeConverger::class, new class implements NodeConverger {
            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void {}
        });

        Node::query()->create([
            'name' => 'operator',
            'status' => LifecycleStatus::Active,
            'public_ssh_host' => '192.0.2.2',
            'wireguard_address' => '10.44.0.2',
        ]);
        $this->withServerVariables(['REMOTE_ADDR' => '10.44.0.2']);
    });

    it('assigns app-dev through the explicit role endpoint', function (): void {
        $node = Node::query()->create([
            'name' => 'app-dev',
            'status' => LifecycleStatus::Active,
            'platform' => 'linux',
            'architecture' => 'x86_64',
            'tld' => 'app-dev.orbit',
            'public_ssh_host' => '192.0.2.40',
            'wireguard_address' => '10.44.0.3',
            'ssh_host_fingerprint' => 'SHA256:pinned',
        ]);
        $requestId = (string) Str::uuid();

        $this
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->postJson("/api/v1/nodes/{$node->id}/roles", ['role' => 'app-dev'])
            ->assertOk()
            ->assertJsonPath('data.node_id', $node->id)
            ->assertJsonPath('data.node_name', 'app-dev')
            ->assertJsonPath('data.assignment.role', 'app-dev')
            ->assertJsonPath('data.assignment.status', 'active')
            ->assertJsonPath('data.assignment.local_action_required', false)
            ->assertJsonPath('data.assignment.local_command', null)
            ->assertJsonPath('meta.request_id', $requestId);
    });

    it('returns HTTP 200 for repeat assignment with one row and one convergence lock', function (): void {
        $lock = new class implements NodeProjectionOperationLock {
            public int $calls = 0;

            public function synchronized(Closure $operation): mixed
            {
                $this->calls++;

                return $operation();
            }
        };
        app()->instance(NodeProjectionOperationLock::class, $lock);
        $node = Node::query()->create([
            'name' => 'app-dev',
            'status' => LifecycleStatus::Active,
            'platform' => 'linux',
            'architecture' => 'x86_64',
            'tld' => 'app-dev.orbit',
            'public_ssh_host' => '192.0.2.40',
            'wireguard_address' => '10.44.0.3',
            'ssh_host_fingerprint' => 'SHA256:pinned',
        ]);

        $this
            ->postJson("/api/v1/nodes/{$node->id}/roles", ['role' => 'app-dev'])
            ->assertOk();
        $this
            ->postJson("/api/v1/nodes/{$node->id}/roles", ['role' => 'app-dev'])
            ->assertOk();

        expect($node->roles()->where('role', RoleName::AppDev->value)->count())
            ->toBe(1)
            ->and($lock->calls)
            ->toBe(2);
    });

    it('publishes only Darwin enrollment projections and returns the local setup lifecycle', function (): void {
        $dns = new class implements PrivateDnsManager {
            public int $calls = 0;

            public function converge(?Node $pendingNode = null): void
            {
                $this->calls++;
            }
        };
        $peers = new class implements GatewayPeerProjectionManager {
            public int $calls = 0;

            public function converge(Node $node): void
            {
                $this->calls++;
            }

            public function remove(Node $node): void {}

            public function restore(Node $node): void {}
        };
        $remote = new class implements NodeConverger {
            public int $calls = 0;

            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void
            {
                $this->calls++;
            }
        };
        app()->instance(PrivateDnsManager::class, $dns);
        app()->instance(GatewayPeerProjectionManager::class, $peers);
        app()->instance(NodeConverger::class, $remote);
        $node = Node::query()->create([
            'name' => 'mini',
            'status' => LifecycleStatus::Active,
            'platform' => 'darwin',
            'architecture' => 'arm64',
            'tld' => 'test',
            'public_ssh_host' => '10.44.0.8',
            'ssh_user' => 'nckrtl',
            'wireguard_address' => '10.44.0.8',
            'wireguard_public_key' => base64_encode(str_repeat(string: "\x01", times: 32)),
        ]);

        $this
            ->postJson("/api/v1/nodes/{$node->id}/roles", ['role' => 'app-dev'])
            ->assertOk()
            ->assertJsonPath('data.assignment.status', 'provisioning')
            ->assertJsonPath('data.assignment.local_action_required', true)
            ->assertJsonPath('data.assignment.local_command', 'orbit node:setup app-dev');

        expect($node->refresh()->status)
            ->toBe(LifecycleStatus::Provisioning)
            ->and($peers->calls)
            ->toBe(1)
            ->and($dns->calls)
            ->toBe(1)
            ->and($remote->calls)
            ->toBe(0);
    });

    it('rejects every role except exact app-dev and preserves stable conflicts', function (): void {
        $node = Node::query()->create([
            'name' => 'gateway',
            'status' => LifecycleStatus::Active,
            'platform' => 'linux',
            'architecture' => 'x86_64',
            'public_ssh_host' => '192.0.2.40',
            'wireguard_address' => '10.44.0.3',
            'ssh_host_fingerprint' => 'SHA256:pinned',
        ]);

        $this
            ->postJson("/api/v1/nodes/{$node->id}/roles", ['role' => 'app-prod'])
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'validation.failed');

        $node->roles()->create(['role' => RoleName::Gateway, 'status' => LifecycleStatus::Active]);

        $this
            ->postJson("/api/v1/nodes/{$node->id}/roles", ['role' => 'app-dev'])
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'node.role_conflict');
    });

    it('fails one empty activity before action execution for invalid raw objects', function (string $json): void {
        $node = Node::query()->create([
            'name' => 'app-dev',
            'status' => LifecycleStatus::Active,
            'platform' => 'linux',
            'architecture' => 'x86_64',
            'tld' => 'app-dev.orbit',
            'public_ssh_host' => '192.0.2.40',
            'wireguard_address' => '10.44.0.3',
            'ssh_host_fingerprint' => 'SHA256:pinned',
        ]);
        $requestId = (string) Str::uuid();

        $response = $this
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->call(
                method: 'POST',
                uri: "/api/v1/nodes/{$node->id}/roles",
                server: [
                    'CONTENT_TYPE' => 'application/json',
                    'HTTP_X_ORBIT_REQUEST_ID' => $requestId,
                ],
                content: $json,
            );

        $response
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'validation.failed');
        $activity = Activity::query()->where('request_id', $requestId)->sole();

        expect($activity->status)
            ->toBe('failed')
            ->and($activity->error_code)
            ->toBe('validation.failed')
            ->and($activity->properties?->get('input'))
            ->toBeEmpty()
            ->and($response->getContent())
            ->not->toContain('RAW_SENTINEL')->and(json_encode($activity->properties?->toArray()))
            ->not->toContain('RAW_SENTINEL')->and($node->roles()->count())->toBe(0);
    })->with([
        'literal duplicate' => ['{"role":"RAW_SENTINEL","role":"app-dev"}'],
        'escaped duplicate' => ['{"role":"RAW_SENTINEL","r\\u006fle":"app-dev"}'],
        'unknown key' => ['{"role":"app-dev","extra":"RAW_SENTINEL"}'],
        'malformed' => ['{"role":"app-dev","extra":"RAW_SENTINEL"'],
    ]);
});
