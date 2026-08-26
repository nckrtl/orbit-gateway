<?php

declare(strict_types=1);

use App\Domain\AppDev\PrivateDnsManager;
use App\Domain\Nodes\NodeConverger;
use App\Domain\Nodes\NodeProvisioningException;
use App\Domain\Shared\LifecycleStatus;
use App\Infrastructure\Processes\CommandResult;
use App\Models\Activity;
use App\Models\Node;
use Illuminate\Support\Str;

/** @mago-expect lint:halstead The API matrix keeps registration, recovery, and activity contracts together. */
describe('POST /api/v1/nodes', function (): void {
    beforeEach(function (): void {
        app()->instance(PrivateDnsManager::class, new class implements PrivateDnsManager {
            public function converge(?Node $pendingNode = null): void {}
        });
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
                'platform' => 'linux',
                'architecture' => 'x86_64',
                'tld' => '.App-Dev.Orbit',
                'roles' => ['app-dev'],
                'host_key_fingerprint' => 'SHA256:'.str_repeat(string: 'A', times: 43),
                'wireguard_endpoint_override' => '10.0.0.2:51820',
                'dns_server_override' => '10.0.0.1',
            ])
            ->assertCreated()
            ->assertJsonPath('data.name', 'app-dev')
            ->assertJsonPath('data.status', 'active')
            ->assertJsonPath('data.platform', 'linux')
            ->assertJsonPath('data.architecture', 'x86_64')
            ->assertJsonPath('data.tld', 'app-dev.orbit')
            ->assertJsonPath('data.wireguard_endpoint_override', '10.0.0.2:51820')
            ->assertJsonPath('data.dns_server_override', '10.0.0.1')
            ->assertJsonPath('data.roles.0', 'app-dev')
            ->assertJsonPath('meta.request_id', $requestId);

        $node = Node::query()->where('name', 'app-dev')->sole();
        $activity = Activity::query()->where('request_id', $requestId)->sole();

        expect($activity->command)
            ->toBe('node:provision')
            ->and($activity->subject_type)
            ->toBe(Node::class)
            ->and($activity->subject_id)
            ->toBe($node->id)
            ->and($activity->target_node_id)
            ->toBe($node->id);
    });

    it('reuses the stored public SSH host when an existing Linux node omits it', function (): void {
        $converger = new class implements NodeConverger {
            public int $calls = 0;

            public ?string $publicSshHost = null;

            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void
            {
                $this->calls++;
                $this->publicSshHost = $node->public_ssh_host;
            }
        };
        app()->instance(NodeConverger::class, $converger);
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
        $node->roles()->create([
            'role' => 'app-dev',
            'status' => LifecycleStatus::Active,
        ]);

        $this
            ->postJson('/api/v1/nodes', [
                'name' => 'app-dev',
                'architecture' => 'x86_64',
                'tld' => 'app-dev.orbit',
                'roles' => ['app-dev'],
            ])
            ->assertCreated()
            ->assertJsonPath('data.public_ssh_host', '192.0.2.40');

        expect($converger->calls)
            ->toBe(1)
            ->and($converger->publicSshHost)
            ->toBe('192.0.2.40')
            ->and($node->refresh()->public_ssh_host)
            ->toBe('192.0.2.40');
    });

    it('returns a stable validation error when a new Linux node omits its public SSH host', function (): void {
        $converger = new class implements NodeConverger {
            public int $calls = 0;

            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void
            {
                $this->calls++;
            }
        };
        app()->instance(NodeConverger::class, $converger);

        $this
            ->postJson('/api/v1/nodes', [
                'name' => 'new-linux-node',
                'platform' => 'linux',
                'architecture' => 'x86_64',
                'host_key_fingerprint' => 'SHA256:'.str_repeat(string: 'A', times: 43),
            ])
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'validation.failed')
            ->assertJsonPath('error.message', 'The request data is invalid.')
            ->assertJsonPath(
                'error.details.public_ssh_host.0',
                'The public SSH host field is required for a new Linux node.',
            );

        expect($converger->calls)
            ->toBe(0)
            ->and(Node::query()->where('name', 'new-linux-node')->exists())
            ->toBeFalse();
    });

    it('uses the request pin as the expectation and returns the observed stored fingerprint', function (): void {
        $observedFingerprint = 'SHA256:'.str_repeat(string: 'B', times: 43);
        $converger = new class($observedFingerprint) implements NodeConverger {
            public ?string $expectedFingerprint = null;

            public function __construct(
                private string $observedFingerprint,
            ) {}

            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void
            {
                $this->expectedFingerprint = $expectedSshHostFingerprint;
                $node->update(['ssh_host_fingerprint' => $this->observedFingerprint]);
            }
        };
        app()->instance(NodeConverger::class, $converger);
        $expectedFingerprint = 'SHA256:'.str_repeat(string: 'A', times: 43);

        $response = $this->postJson('/api/v1/nodes', [
            'name' => 'roleless-operator',
            'public_ssh_host' => '192.0.2.61',
            'architecture' => 'x86_64',
            'host_key_fingerprint' => $expectedFingerprint,
        ]);

        $response
            ->assertCreated()
            ->assertJsonPath('data.ssh_host_fingerprint', $observedFingerprint)
            ->assertJsonMissingPath('data.host_key_fingerprint');

        $node = Node::query()->where('name', 'roleless-operator')->sole();

        expect($converger->expectedFingerprint)
            ->toBe($expectedFingerprint)
            ->and($node->ssh_host_fingerprint)
            ->toBe($observedFingerprint);
    });

    it('requires a unique valid TLD for app-dev nodes', function (): void {
        app()->instance(NodeConverger::class, new class implements NodeConverger {
            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void {}
        });
        Node::query()->create([
            'name' => 'existing-dev',
            'public_ssh_host' => '192.0.2.40',
            'tld' => 'test',
        ]);
        $fingerprint = 'SHA256:'.str_repeat(string: 'A', times: 43);

        $this
            ->postJson('/api/v1/nodes', [
                'name' => 'missing-tld',
                'public_ssh_host' => '192.0.2.41',
                'architecture' => 'x86_64',
                'roles' => ['app-dev'],
                'host_key_fingerprint' => $fingerprint,
            ])
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'node.tld_required');

        $this
            ->postJson('/api/v1/nodes', [
                'name' => 'invalid-tld',
                'public_ssh_host' => '192.0.2.42',
                'roles' => ['app-dev'],
                'tld' => 'not valid',
                'host_key_fingerprint' => $fingerprint,
            ])
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'validation.failed');

        $this
            ->postJson('/api/v1/nodes', [
                'name' => 'duplicate-tld',
                'public_ssh_host' => '192.0.2.43',
                'architecture' => 'x86_64',
                'roles' => ['app-dev'],
                'tld' => 'TEST',
                'host_key_fingerprint' => $fingerprint,
            ])
            ->assertConflict()
            ->assertJsonPath('error.code', 'node.tld_taken');
    });

    it('rejects unsupported platforms and invalid architectures at the API boundary', function (): void {
        $fingerprint = 'SHA256:'.str_repeat(string: 'A', times: 43);

        $this
            ->postJson('/api/v1/nodes', [
                'name' => 'windows-node',
                'public_ssh_host' => '192.0.2.44',
                'platform' => 'windows',
                'host_key_fingerprint' => $fingerprint,
            ])
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'validation.failed');

        $this
            ->postJson('/api/v1/nodes', [
                'name' => 'invalid-architecture',
                'public_ssh_host' => '192.0.2.45',
                'architecture' => 'arm64; touch /tmp/orbit',
                'host_key_fingerprint' => $fingerprint,
            ])
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'validation.failed');
    });

    it('registers Darwin app-dev work as provisioning for a later local action', function (): void {
        $converger = new class implements NodeConverger {
            public int $calls = 0;

            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void
            {
                $this->calls++;
            }
        };
        app()->instance(NodeConverger::class, $converger);

        $this
            ->postJson('/api/v1/nodes', [
                'name' => 'mac-dev',
                'platform' => 'darwin',
                'architecture' => 'arm64',
                'tld' => 'mac.test',
                'roles' => ['app-dev'],
            ])
            ->assertCreated()
            ->assertJsonPath('data.status', 'provisioning')
            ->assertJsonPath('data.platform', 'darwin')
            ->assertJsonPath('data.architecture', 'arm64')
            ->assertJsonPath('data.tld', 'mac.test')
            ->assertJsonPath('data.public_ssh_host', '10.44.0.1')
            ->assertJsonPath('data.roles.0', 'app-dev');

        $node = Node::query()->where('name', 'mac-dev')->sole();

        expect($node->roles()->sole()->status)
            ->toBe(LifecycleStatus::Provisioning)
            ->and($converger->calls)
            ->toBe(0);
    });

    it('returns a stable error when Darwin architecture is missing', function (): void {
        $this
            ->postJson('/api/v1/nodes', [
                'name' => 'mac-dev',
                'public_ssh_host' => '10.44.0.8',
                'platform' => 'darwin',
                'tld' => 'mac.test',
                'roles' => ['app-dev'],
            ])
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'node.architecture_required');

        expect(Node::query()->where('name', 'mac-dev')->exists())->toBeFalse();
    });

    it('returns a stable error when Linux architecture is missing', function (): void {
        $this
            ->postJson('/api/v1/nodes', [
                'name' => 'linux-node',
                'public_ssh_host' => '192.0.2.60',
                'host_key_fingerprint' => 'SHA256:'.str_repeat(string: 'A', times: 43),
            ])
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'node.architecture_required');

        expect(Node::query()->where('name', 'linux-node')->exists())->toBeFalse();
    });

    it('rejects an unsafe WireGuard endpoint override at the API boundary', function (): void {
        $this
            ->postJson('/api/v1/nodes', [
                'name' => 'unsafe-endpoint',
                'public_ssh_host' => '192.0.2.46',
                'wireguard_endpoint_override' => "10.0.0.2:51820\nPostUp = touch /tmp/orbit-injected",
                'host_key_fingerprint' => 'SHA256:'.str_repeat(string: 'A', times: 43),
            ])
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'validation.failed');

        expect(Node::query()->where('name', 'unsafe-endpoint')->exists())->toBeFalse();
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
                'architecture' => 'x86_64',
                'roles' => ['app-dev'],
                'tld' => 'app-dev.orbit',
            ])
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'node.ssh_host_fingerprint_required');

        expect(Node::query()->where('name', 'app-dev')->exists())->toBeFalse();
    });

    it('returns a bounded 502 mismatch error without echoing either fingerprint', function (): void {
        $expectedFingerprint = 'SHA256:'.str_repeat(string: 'A', times: 43);
        $observedFingerprint = 'SHA256:'.str_repeat(string: 'B', times: 43);
        $converger = new class implements NodeConverger {
            public ?string $expectedFingerprint = null;

            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void
            {
                $this->expectedFingerprint = $expectedSshHostFingerprint;

                throw new NodeProvisioningException(
                    step: 'ssh-host-key',
                    errorCode: 'node.ssh_host_key_mismatch',
                    message: "The SSH host fingerprint did not match for node [{$node->name}].",
                );
            }
        };
        app()->instance(NodeConverger::class, $converger);

        $response = $this->postJson('/api/v1/nodes', [
            'name' => 'mismatch-node',
            'public_ssh_host' => '192.0.2.62',
            'architecture' => 'x86_64',
            'host_key_fingerprint' => $expectedFingerprint,
        ]);

        $response
            ->assertStatus(502)
            ->assertJsonPath('error.code', 'node.ssh_host_key_mismatch')
            ->assertJsonPath('error.message', 'The SSH host fingerprint did not match for node [mismatch-node].')
            ->assertJsonPath('error.details.step', 'ssh-host-key');

        $node = Node::query()->where('name', 'mismatch-node')->sole();

        expect($response->getContent())
            ->not
            ->toContain($expectedFingerprint, $observedFingerprint)
            ->and($converger->expectedFingerprint)
            ->toBe($expectedFingerprint)
            ->and($node->ssh_host_fingerprint)
            ->toBeNull()
            ->and($node->status)
            ->toBe(LifecycleStatus::Failed)
            ->and($node->error_code)
            ->toBe('node.ssh_host_key_mismatch');
    });

    it('keeps empty-string normalization for other nullable node fields', function (): void {
        app()->instance(NodeConverger::class, new class implements NodeConverger {
            public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void {}
        });

        $this
            ->postJson('/api/v1/nodes', [
                'name' => 'normalized-overrides',
                'public_ssh_host' => '192.0.2.30',
                'architecture' => 'x86_64',
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
                'architecture' => 'x86_64',
                'wireguard_address' => '10.45.0.2',
                'host_key_fingerprint' => $fingerprint,
            ])
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'vpn.peer_address_invalid');

        $this
            ->postJson('/api/v1/nodes', [
                'name' => 'blank',
                'public_ssh_host' => '192.0.2.24',
                'architecture' => 'x86_64',
                'wireguard_address' => '',
                'host_key_fingerprint' => $fingerprint,
            ])
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'vpn.peer_address_invalid');

        $this
            ->postJson('/api/v1/nodes', [
                'name' => 'whitespace',
                'public_ssh_host' => '192.0.2.25',
                'architecture' => 'x86_64',
                'wireguard_address' => '   ',
                'host_key_fingerprint' => $fingerprint,
            ])
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'vpn.peer_address_invalid');

        $this
            ->postJson('/api/v1/nodes', [
                'name' => 'malformed',
                'public_ssh_host' => '192.0.2.22',
                'architecture' => 'x86_64',
                'wireguard_address' => 'not-an-address',
                'host_key_fingerprint' => $fingerprint,
            ])
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'vpn.peer_address_invalid');

        $this
            ->postJson('/api/v1/nodes', [
                'name' => 'ipv6',
                'public_ssh_host' => '192.0.2.23',
                'architecture' => 'x86_64',
                'wireguard_address' => 'fd00::2',
                'host_key_fingerprint' => $fingerprint,
            ])
            ->assertUnprocessable()
            ->assertJsonPath('error.code', 'vpn.peer_address_invalid');

        $this
            ->postJson('/api/v1/nodes', [
                'name' => 'duplicate',
                'public_ssh_host' => '192.0.2.21',
                'architecture' => 'x86_64',
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
                'architecture' => 'x86_64',
                'roles' => ['app-dev'],
                'tld' => 'app-dev.orbit',
                'host_key_fingerprint' => 'SHA256:'.str_repeat(string: 'A', times: 43),
            ])
            ->assertStatus(502)
            ->assertJsonPath('error.code', 'node.bootstrap_failed')
            ->assertJsonPath('error.details.step', 'base-host');

        $activity = Activity::query()->where('request_id', $requestId)->sole();
        $node = Node::query()->where('name', 'app-dev')->sole();

        expect($activity->exit_code)
            ->toBe(12)
            ->and($activity->subject_type)
            ->toBe(Node::class)
            ->and($activity->subject_id)
            ->toBe($node->id)
            ->and($activity->target_node_id)
            ->toBe($node->id)
            ->and($activity->properties?->get('stdout'))
            ->toBe('partial')
            ->and($activity->properties?->get('stderr'))
            ->toBe('apt failed');
    });
});
