<?php

declare(strict_types=1);

use App\Domain\Nodes\NodeConverger;
use App\Domain\Nodes\NodeProvisioningException;
use App\Domain\Shared\LifecycleStatus;
use App\Infrastructure\Processes\CommandResult;
use App\Models\Activity;
use App\Models\Node;
use Illuminate\Support\Str;

describe('POST /api/v1/nodes', function (): void {
    beforeEach(function (): void {
        Node::query()->create([
            'name' => 'operator',
            'status' => LifecycleStatus::Active,
            'public_ssh_host' => '192.0.2.2',
            'wireguard_address' => '10.44.0.2',
        ]);
        $this->withServerVariables(['REMOTE_ADDR' => '10.44.0.2']);
    });

    it('provisions a node through the gateway action', function (): void {
        app()->instance(NodeConverger::class, new class implements NodeConverger {
            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void {}
        });
        $requestId = (string) Str::uuid();

        $this
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->postJson('/api/v1/nodes', [
                'name' => 'app-dev',
                'public_ssh_host' => '94.237.40.75',
                'roles' => ['app-dev'],
                'host_key_fingerprint' => 'SHA256:'.str_repeat(string: 'A', times: 43),
                'wireguard_endpoint_override' => '10.0.0.2:51820',
                'dns_server_override' => '10.0.0.1',
            ])
            ->assertCreated()
            ->assertJsonPath('data.name', 'app-dev')
            ->assertJsonPath('data.status', 'active')
            ->assertJsonPath('data.roles.0', 'app-dev')
            ->assertJsonPath('meta.request_id', $requestId);

        expect(Activity::query()->where('request_id', $requestId)->sole()->command)
            ->toBe('node:provision');
    });

    it('returns the standard validation envelope and records rejection', function (): void {
        $requestId = (string) Str::uuid();

        $this
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->postJson('/api/v1/nodes', [
                'name' => 'not valid',
                'roles' => ['unknown'],
                'host_key_fingerprint' => 'SHA256:'.str_repeat(string: 'A', times: 43),
            ])
            ->assertUnprocessable()
            ->assertHeader('X-Orbit-Request-Id', $requestId)
            ->assertJsonPath('error.code', 'validation.failed')
            ->assertJsonStructure(['error' => ['code', 'message', 'details']]);

        $activity = Activity::query()->where('request_id', $requestId)->sole();

        expect($activity->command)
            ->toBe('node:provision')
            ->and($activity->status)
            ->toBe('failed')
            ->and($activity->error_code)
            ->toBe('validation.failed');
    });

    it('requires an expected fingerprint before persisting a new node', function (): void {
        $this
            ->postJson('/api/v1/nodes', [
                'name' => 'app-dev',
                'public_ssh_host' => '94.237.40.75',
                'roles' => ['app-dev'],
            ])
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'node.ssh_host_fingerprint_required');

        expect(Node::query()->where('name', 'app-dev')->exists())->toBeFalse();
    });

    it('keeps empty-string normalization for other nullable node fields', function (): void {
        app()->instance(NodeConverger::class, new class implements NodeConverger {
            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void {}
        });

        $this
            ->postJson('/api/v1/nodes', [
                'name' => 'normalized-overrides',
                'public_ssh_host' => '192.0.2.30',
                'wireguard_address' => '10.44.0.3',
                'wireguard_endpoint_override' => '',
                'dns_server_override' => '',
                'host_key_fingerprint' => 'SHA256:'.str_repeat(string: 'A', times: 43),
            ])
            ->assertCreated();

        $node = Node::query()->where('name', 'normalized-overrides')->sole();

        expect($node->wireguard_endpoint_override)
            ->toBeNull()
            ->and($node->dns_server_override)
            ->toBeNull();
    });

    it('rejects invalid and assigned WireGuard peer addresses before convergence', function (): void {
        $converger = new class implements NodeConverger {
            public int $calls = 0;

            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void
            {
                $this->calls++;
            }
        };
        app()->instance(NodeConverger::class, $converger);
        $fingerprint = 'SHA256:'.str_repeat(string: 'A', times: 43);

        $this
            ->postJson('/api/v1/nodes', [
                'name' => 'outside',
                'public_ssh_host' => '192.0.2.20',
                'wireguard_address' => '10.45.0.2',
                'host_key_fingerprint' => $fingerprint,
            ])
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'vpn.peer_address_invalid');

        $this
            ->postJson('/api/v1/nodes', [
                'name' => 'blank',
                'public_ssh_host' => '192.0.2.24',
                'wireguard_address' => '',
                'host_key_fingerprint' => $fingerprint,
            ])
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'vpn.peer_address_invalid');

        $this
            ->postJson('/api/v1/nodes', [
                'name' => 'whitespace',
                'public_ssh_host' => '192.0.2.25',
                'wireguard_address' => '   ',
                'host_key_fingerprint' => $fingerprint,
            ])
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'vpn.peer_address_invalid');

        $this
            ->postJson('/api/v1/nodes', [
                'name' => 'malformed',
                'public_ssh_host' => '192.0.2.22',
                'wireguard_address' => 'not-an-address',
                'host_key_fingerprint' => $fingerprint,
            ])
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'vpn.peer_address_invalid');

        $this
            ->postJson('/api/v1/nodes', [
                'name' => 'ipv6',
                'public_ssh_host' => '192.0.2.23',
                'wireguard_address' => 'fd00::2',
                'host_key_fingerprint' => $fingerprint,
            ])
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'vpn.peer_address_invalid');

        $this
            ->postJson('/api/v1/nodes', [
                'name' => 'duplicate',
                'public_ssh_host' => '192.0.2.21',
                'wireguard_address' => '10.44.0.2',
                'host_key_fingerprint' => $fingerprint,
            ])
            ->assertConflict()
            ->assertJsonPath('error.code', 'vpn.peer_address_taken');

        expect(
            Node::query()
                ->whereIn(
                    'name',
                    ['outside', 'blank', 'whitespace', 'malformed', 'ipv6', 'duplicate'],
                )
                ->exists(),
        )
            ->toBeFalse()
            ->and($converger->calls)
            ->toBe(0);
    });

    it('records bounded native failure metadata', function (): void {
        app()->instance(NodeConverger::class, new class implements NodeConverger {
            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void
            {
                throw new NodeProvisioningException(
                    step: 'base-host',
                    errorCode: 'node.bootstrap_failed',
                    message: 'Could not bootstrap the node.',
                    result: new CommandResult(12, 'partial', 'apt failed', 50, false),
                );
            }
        });
        $requestId = (string) Str::uuid();

        $this
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->postJson('/api/v1/nodes', [
                'name' => 'app-dev',
                'public_ssh_host' => '94.237.40.75',
                'roles' => ['app-dev'],
                'host_key_fingerprint' => 'SHA256:'.str_repeat(string: 'A', times: 43),
            ])
            ->assertStatus(502)
            ->assertJsonPath('error.code', 'node.bootstrap_failed')
            ->assertJsonPath('error.details.step', 'base-host');

        $activity = Activity::query()->where('request_id', $requestId)->sole();

        expect($activity->exit_code)
            ->toBe(12)
            ->and($activity->properties?->get('stdout'))
            ->toBe('partial')
            ->and($activity->properties?->get('stderr'))
            ->toBe('apt failed');
    });
});
