<?php

declare(strict_types=1);

use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Models\Activity;
use App\Models\Node;
use App\Models\NodeRole;
use Illuminate\Support\Str;

describe('GET /api/v1/nodes', function (): void {
    it('returns an empty collection in the standard envelope', function (): void {
        $requestId = (string) Str::uuid();

        $this
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->getJson('/api/v1/nodes')
            ->assertOk()
            ->assertHeader('X-Orbit-Request-Id', $requestId)
            ->assertExactJson([
                'data' => [],
                'meta' => ['request_id' => $requestId],
            ]);

        $activity = Activity::query()->sole();

        expect($activity->command)
            ->toBe('node.list')
            ->and($activity->status)
            ->toBe('succeeded');
    });

    it('returns nodes in deterministic name order with typed serialized fields', function (): void {
        $zulu = Node::query()->create([
            'name' => 'zulu',
            'status' => LifecycleStatus::Failed,
            'platform' => 'ubuntu',
            'architecture' => 'arm64',
            'public_ssh_host' => '203.0.113.20',
            'public_ssh_port' => 2202,
            'ssh_user' => 'orbit',
            'wireguard_address' => '10.0.0.22',
            'wireguard_public_key' => 'wg-zulu-public',
            'wireguard_endpoint_override' => 'vpn.example.com:51820',
            'dns_server_override' => '10.0.0.53',
            'ssh_host_key_type' => 'ssh-ed25519',
            'ssh_host_key' => 'ssh-ed25519 AAAA-secret-zulu',
            'ssh_host_fingerprint' => 'SHA256:zulu',
            'failed_step' => 'wireguard',
            'error_code' => 'vpn.peer_address_missing',
        ]);
        $alpha = Node::query()->create([
            'name' => 'alpha',
            'status' => LifecycleStatus::Active,
            'platform' => 'ubuntu',
            'architecture' => 'x86_64',
            'public_ssh_host' => '203.0.113.10',
            'public_ssh_port' => 22,
            'ssh_user' => 'root',
            'wireguard_address' => '10.0.0.11',
            'wireguard_public_key' => 'wg-alpha-public',
            'wireguard_endpoint_override' => 'private.example.com:51820',
            'dns_server_override' => '10.0.0.1',
            'ssh_host_key_type' => 'ssh-ed25519',
            'ssh_host_key' => 'ssh-ed25519 AAAA-secret-alpha',
            'ssh_host_fingerprint' => 'SHA256:alpha',
        ]);

        NodeRole::query()->create([
            'node_id' => $zulu->id,
            'role' => RoleName::Vpn,
            'status' => LifecycleStatus::Failed,
        ]);
        NodeRole::query()->create([
            'node_id' => $alpha->id,
            'role' => RoleName::AppDev,
            'status' => LifecycleStatus::Active,
        ]);
        NodeRole::query()->create([
            'node_id' => $alpha->id,
            'role' => RoleName::Gateway,
            'status' => LifecycleStatus::Active,
        ]);

        $requestId = (string) Str::uuid();

        $response = $this
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->getJson('/api/v1/nodes');

        $response
            ->assertOk()
            ->assertHeader('X-Orbit-Request-Id', $requestId)
            ->assertJsonPath('meta.request_id', $requestId)
            ->assertJsonPath('data.0.name', 'alpha')
            ->assertJsonPath('data.1.name', 'zulu')
            ->assertJsonPath('data.0.roles', ['gateway', 'app-dev'])
            ->assertJsonPath('data.1.roles', ['vpn'])
            ->assertJsonPath('data.0.platform', 'ubuntu')
            ->assertJsonPath('data.0.architecture', 'x86_64')
            ->assertJsonPath('data.0.public_ssh_host', '203.0.113.10')
            ->assertJsonPath('data.0.public_ssh_port', 22)
            ->assertJsonPath('data.0.ssh_user', 'root')
            ->assertJsonPath('data.0.wireguard_address', '10.0.0.11')
            ->assertJsonPath('data.0.ssh_host_fingerprint', 'SHA256:alpha')
            ->assertJsonMissingPath('data.0.wireguard_public_key')
            ->assertJsonMissingPath('data.0.wireguard_endpoint_override')
            ->assertJsonMissingPath('data.0.dns_server_override')
            ->assertJsonMissingPath('data.0.ssh_host_key')
            ->assertJsonStructure([
                'data' => [[
                    'id',
                    'name',
                    'status',
                    'platform',
                    'architecture',
                    'public_ssh_host',
                    'public_ssh_port',
                    'ssh_user',
                    'wireguard_address',
                    'ssh_host_fingerprint',
                    'failed_step',
                    'error_code',
                    'roles',
                ]],
                'meta' => ['request_id'],
            ]);
    });
});

describe('GET /api/v1/nodes/{node}', function (): void {
    it('shows one node in the standard envelope without secret fields', function (): void {
        $node = Node::query()->create([
            'name' => 'alpha',
            'status' => LifecycleStatus::Active,
            'platform' => 'ubuntu',
            'architecture' => 'x86_64',
            'public_ssh_host' => '203.0.113.10',
            'public_ssh_port' => 22,
            'ssh_user' => 'root',
            'wireguard_address' => '10.0.0.11',
            'wireguard_public_key' => 'wg-alpha-public',
            'wireguard_endpoint_override' => 'private.example.com:51820',
            'dns_server_override' => '10.0.0.1',
            'ssh_host_key_type' => 'ssh-ed25519',
            'ssh_host_key' => 'ssh-ed25519 AAAA-secret-alpha',
            'ssh_host_fingerprint' => 'SHA256:alpha',
        ]);
        NodeRole::query()->create([
            'node_id' => $node->id,
            'role' => RoleName::Gateway,
            'status' => LifecycleStatus::Active,
        ]);

        $requestId = (string) Str::uuid();

        $this
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->getJson("/api/v1/nodes/{$node->id}")
            ->assertOk()
            ->assertHeader('X-Orbit-Request-Id', $requestId)
            ->assertJsonPath('data.id', $node->id)
            ->assertJsonPath('data.name', 'alpha')
            ->assertJsonPath('data.roles', ['gateway'])
            ->assertJsonPath('meta.request_id', $requestId)
            ->assertJsonMissingPath('data.wireguard_public_key')
            ->assertJsonMissingPath('data.wireguard_endpoint_override')
            ->assertJsonMissingPath('data.dns_server_override')
            ->assertJsonMissingPath('data.ssh_host_key');

        $activity = Activity::query()->sole();

        expect($activity->command)
            ->toBe('node.show')
            ->and($activity->status)
            ->toBe('succeeded');
    });

    it('returns the existing error envelope when the node is unknown', function (): void {
        $requestId = (string) Str::uuid();

        $this
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->getJson('/api/v1/nodes/999999')
            ->assertNotFound()
            ->assertHeader('X-Orbit-Request-Id', $requestId)
            ->assertJsonPath('error.code', 'http.404')
            ->assertJsonPath('error.message', 'Resource not found.')
            ->assertJsonPath('error.details', []);

        $activity = Activity::query()->sole();

        expect($activity->command)
            ->toBe('node.show')
            ->and($activity->status)
            ->toBe('failed')
            ->and($activity->error_code)
            ->toBe('http.404');
    });
});
