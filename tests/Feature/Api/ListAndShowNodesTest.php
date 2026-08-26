<?php

declare(strict_types=1);

use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Models\Activity;
use App\Models\Node;
use App\Models\NodeRole;
use Illuminate\Support\Str;

describe('GET /api/v1/nodes caller envelope', function (): void {
    it('lists the active caller in the standard envelope when no other nodes exist', function (): void {
        $operator = $this->markAsGateway(Node::query()->create([
            'name' => 'operator',
            'status' => LifecycleStatus::Active,
            'public_ssh_host' => '192.0.2.2',
            'wireguard_address' => '10.44.0.2',
        ]));
        $requestId = (string) Str::uuid();

        $this
            ->withServerVariables(['REMOTE_ADDR' => $operator->wireguard_address])
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->getJson('/api/v1/nodes')
            ->assertOk()
            ->assertHeader('X-Orbit-Request-Id', $requestId)
            ->assertJsonCount(1, 'data')
            ->assertJsonPath('data.0.id', $operator->id)
            ->assertJsonPath('data.0.name', 'operator')
            ->assertJsonPath('meta.request_id', $requestId);

        $activity = Activity::query()->sole();

        expect($activity->command)
            ->toBe('node:list')
            ->and($activity->status)
            ->toBe('succeeded')
            ->and($activity->caller_node_id)
            ->toBe($operator->id);
    });
});

describe('GET /api/v1/nodes serialization', function (): void {
    it('lists nodes in deterministic name order with typed serialized fields', function (): void {
        $zulu = Node::query()->create([
            'name' => 'zulu',
            'status' => LifecycleStatus::Failed,
            'platform' => 'ubuntu',
            'architecture' => 'arm64',
            'tld' => 'zulu.orbit',
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
            'tld' => 'alpha.orbit',
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
            ->withServerVariables(['REMOTE_ADDR' => $alpha->wireguard_address])
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
            ->assertJsonPath('data.0.tld', 'alpha.orbit')
            ->assertJsonPath('data.0.public_ssh_host', '203.0.113.10')
            ->assertJsonPath('data.0.public_ssh_port', 22)
            ->assertJsonPath('data.0.ssh_user', 'root')
            ->assertJsonPath('data.0.wireguard_address', '10.0.0.11')
            ->assertJsonPath('data.0.ssh_host_fingerprint', 'SHA256:alpha')
            ->assertJsonMissingPath('data.0.host_key_fingerprint')
            ->assertJsonPath('data.0.wireguard_public_key', 'wg-alpha-public')
            ->assertJsonPath('data.0.wireguard_endpoint_override', 'private.example.com:51820')
            ->assertJsonPath('data.0.dns_server_override', '10.0.0.1')
            ->assertJsonMissingPath('data.0.ssh_host_key')
            ->assertJsonStructure([
                'data' => [[
                    'id',
                    'name',
                    'status',
                    'platform',
                    'architecture',
                    'tld',
                    'public_ssh_host',
                    'public_ssh_port',
                    'ssh_user',
                    'wireguard_address',
                    'wireguard_public_key',
                    'wireguard_endpoint_override',
                    'dns_server_override',
                    'ssh_host_fingerprint',
                    'failed_step',
                    'error_code',
                    'roles',
                ]],
                'meta' => ['request_id'],
            ]);
    });
});

/** @mago-expect lint:halstead The API group keeps the node show serialization and access projection together. */
describe('GET /api/v1/nodes/{node}', function (): void {
    it('shows one node in the standard envelope without secret fields', function (): void {
        $node = $this->markAsGateway(Node::query()->create([
            'name' => 'alpha',
            'status' => LifecycleStatus::Active,
            'platform' => 'ubuntu',
            'architecture' => 'x86_64',
            'tld' => 'alpha.orbit',
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
        ]));

        $requestId = (string) Str::uuid();

        $this
            ->withServerVariables(['REMOTE_ADDR' => $node->wireguard_address])
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->getJson("/api/v1/nodes/{$node->id}")
            ->assertOk()
            ->assertHeader('X-Orbit-Request-Id', $requestId)
            ->assertJsonPath('data.id', $node->id)
            ->assertJsonPath('data.name', 'alpha')
            ->assertJsonPath('data.roles', ['gateway'])
            ->assertJsonPath('data.tld', 'alpha.orbit')
            ->assertJsonPath('data.wireguard_public_key', 'wg-alpha-public')
            ->assertJsonPath('data.wireguard_endpoint_override', 'private.example.com:51820')
            ->assertJsonPath('data.dns_server_override', '10.0.0.1')
            ->assertJsonPath('data.ssh_host_fingerprint', 'SHA256:alpha')
            ->assertJsonMissingPath('data.host_key_fingerprint')
            ->assertJsonPath('meta.request_id', $requestId)
            ->assertJsonMissingPath('data.ssh_host_key');

        $activity = Activity::query()->sole();

        expect($activity->command)
            ->toBe('node:show')
            ->and($activity->status)
            ->toBe('succeeded');
    });

    it('returns the existing error envelope when the node is unknown', function (): void {
        $operator = $this->markAsGateway(Node::query()->create([
            'name' => 'operator',
            'status' => LifecycleStatus::Active,
            'public_ssh_host' => '192.0.2.2',
            'wireguard_address' => '10.44.0.2',
        ]));
        $requestId = (string) Str::uuid();

        $this
            ->withServerVariables(['REMOTE_ADDR' => $operator->wireguard_address])
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->getJson('/api/v1/nodes/999999')
            ->assertNotFound()
            ->assertHeader('X-Orbit-Request-Id', $requestId)
            ->assertJsonPath('error.code', 'http.404')
            ->assertJsonPath('error.message', 'Resource not found.')
            ->assertJsonPath('error.details', []);

        $activity = Activity::query()->sole();

        expect($activity->command)
            ->toBe('node:show')
            ->and($activity->status)
            ->toBe('failed')
            ->and($activity->error_code)
            ->toBe('http.404');
    });

    it('shows stored outbound and inbound access summaries in stable node id order', function (): void {
        $operator = $this->markAsGateway(Node::query()->create([
            'name' => 'operator',
            'status' => LifecycleStatus::Active,
            'public_ssh_host' => '192.0.2.20',
            'wireguard_address' => '10.44.0.20',
        ]));
        $node = Node::query()->create([
            'name' => 'serving-node',
            'status' => LifecycleStatus::Active,
            'public_ssh_host' => '192.0.2.21',
            'wireguard_address' => '10.44.0.21',
        ]);
        $zuluOutbound = Node::query()->create([
            'name' => 'zulu-outbound',
            'status' => LifecycleStatus::Active,
            'public_ssh_host' => '192.0.2.22',
            'wireguard_address' => '10.44.0.22',
        ]);
        $alphaOutbound = Node::query()->create([
            'name' => 'alpha-outbound',
            'status' => LifecycleStatus::Active,
            'public_ssh_host' => '192.0.2.23',
            'wireguard_address' => '10.44.0.23',
        ]);
        $zuluInbound = Node::query()->create([
            'name' => 'zulu-inbound',
            'status' => LifecycleStatus::Active,
            'public_ssh_host' => '192.0.2.24',
            'wireguard_address' => '10.44.0.24',
        ]);
        $alphaInbound = Node::query()->create([
            'name' => 'alpha-inbound',
            'status' => LifecycleStatus::Active,
            'public_ssh_host' => '192.0.2.25',
            'wireguard_address' => '10.44.0.25',
        ]);

        $node->accessibleNodes()->attach([$alphaOutbound->id, $zuluOutbound->id]);
        $node->accessingNodes()->attach([$alphaInbound->id, $zuluInbound->id]);

        $this
            ->withServerVariables(['REMOTE_ADDR' => $operator->wireguard_address])
            ->getJson("/api/v1/nodes/{$node->id}")
            ->assertOk()
            ->assertJsonPath('data.access.can_access', [
                ['id' => $zuluOutbound->id, 'name' => 'zulu-outbound'],
                ['id' => $alphaOutbound->id, 'name' => 'alpha-outbound'],
            ])
            ->assertJsonPath('data.access.accessible_by', [
                ['id' => $zuluInbound->id, 'name' => 'zulu-inbound'],
                ['id' => $alphaInbound->id, 'name' => 'alpha-inbound'],
            ]);
    });

    it('shows empty access arrays when a node has no stored edges', function (): void {
        $operator = $this->markAsGateway(Node::query()->create([
            'name' => 'operator',
            'status' => LifecycleStatus::Active,
            'public_ssh_host' => '192.0.2.30',
            'wireguard_address' => '10.44.0.30',
        ]));
        $node = Node::query()->create([
            'name' => 'isolated-node',
            'status' => LifecycleStatus::Active,
            'public_ssh_host' => '192.0.2.31',
            'wireguard_address' => '10.44.0.31',
        ]);

        $this
            ->withServerVariables(['REMOTE_ADDR' => $operator->wireguard_address])
            ->getJson("/api/v1/nodes/{$node->id}")
            ->assertOk()
            ->assertJsonPath('data.access.can_access', [])
            ->assertJsonPath('data.access.accessible_by', []);
    });
});

describe('GET /api/v1/nodes collection access', function (): void {
    it('shows all rows to fleet authority, one serving node to a direct consumer, and denies a no-edge consumer', function (): void {
        $gateway = $this->markAsGateway(Node::query()->create([
            'name' => 'gateway',
            'status' => LifecycleStatus::Active,
            'public_ssh_host' => '192.0.2.10',
            'wireguard_address' => '10.44.0.10',
        ]));
        $first = Node::query()->create([
            'name' => 'alpha',
            'status' => LifecycleStatus::Active,
            'public_ssh_host' => '192.0.2.11',
            'wireguard_address' => '10.44.0.11',
        ]);
        $second = Node::query()->create([
            'name' => 'zulu',
            'status' => LifecycleStatus::Active,
            'public_ssh_host' => '192.0.2.12',
            'wireguard_address' => '10.44.0.12',
        ]);
        $directConsumer = Node::query()->create([
            'name' => 'direct-consumer',
            'status' => LifecycleStatus::Active,
            'public_ssh_host' => '192.0.2.13',
            'wireguard_address' => '10.44.0.13',
        ]);
        $gatewayAccessConsumer = Node::query()->create([
            'name' => 'gateway-access-consumer',
            'status' => LifecycleStatus::Active,
            'public_ssh_host' => '192.0.2.14',
            'wireguard_address' => '10.44.0.14',
        ]);
        $noEdgeConsumer = Node::query()->create([
            'name' => 'no-edge-consumer',
            'status' => LifecycleStatus::Active,
            'public_ssh_host' => '192.0.2.15',
            'wireguard_address' => '10.44.0.15',
        ]);
        $directConsumer->accessibleNodes()->attach($second);
        $gatewayAccessConsumer->accessibleNodes()->attach($gateway);

        $this
            ->withServerVariables(['REMOTE_ADDR' => $gateway->wireguard_address])
            ->getJson('/api/v1/nodes')
            ->assertOk()
            ->assertJsonPath('data.*.id', [
                $first->id,
                $directConsumer->id,
                $gateway->id,
                $gatewayAccessConsumer->id,
                $noEdgeConsumer->id,
                $second->id,
            ]);

        $this
            ->withServerVariables(['REMOTE_ADDR' => $gatewayAccessConsumer->wireguard_address])
            ->getJson('/api/v1/nodes')
            ->assertOk()
            ->assertJsonPath('data.*.id', [
                $first->id,
                $directConsumer->id,
                $gateway->id,
                $gatewayAccessConsumer->id,
                $noEdgeConsumer->id,
                $second->id,
            ]);

        $this
            ->withServerVariables(['REMOTE_ADDR' => $directConsumer->wireguard_address])
            ->getJson('/api/v1/nodes')
            ->assertOk()
            ->assertJsonPath('data.*.id', [$second->id]);

        $this
            ->withServerVariables(['REMOTE_ADDR' => $noEdgeConsumer->wireguard_address])
            ->getJson('/api/v1/nodes')
            ->assertForbidden()
            ->assertJsonPath('error.code', 'node_access.required');
    });

    it('keeps node list serialization free of access data', function (): void {
        $operator = $this->markAsGateway(Node::query()->create([
            'name' => 'operator',
            'status' => LifecycleStatus::Active,
            'public_ssh_host' => '192.0.2.40',
            'wireguard_address' => '10.44.0.40',
        ]));
        Node::query()->create([
            'name' => 'listed-node',
            'status' => LifecycleStatus::Active,
            'public_ssh_host' => '192.0.2.41',
            'wireguard_address' => '10.44.0.41',
        ]);

        $this
            ->withServerVariables(['REMOTE_ADDR' => $operator->wireguard_address])
            ->getJson('/api/v1/nodes')
            ->assertOk()
            ->assertJsonMissingPath('data.0.access')
            ->assertJsonMissingPath('data.1.access');
    });
});
