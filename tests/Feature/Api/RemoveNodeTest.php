<?php

declare(strict_types=1);

use App\Domain\AppDev\PrivateDnsManager;
use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Domain\WireGuard\GatewayPeerProjectionManager;
use App\Models\Activity;
use App\Models\App as OrbitApp;
use App\Models\FirewallRule;
use App\Models\Instance;
use App\Models\Node;
use App\Models\NodeRole;

beforeEach(function (): void {
    $this->dns = new RemoveNodeFakeDnsManager;
    $this->peers = new RemoveNodeFakePeerProjection;
    app()->instance(PrivateDnsManager::class, $this->dns);
    app()->instance('App\\Domain\\WireGuard\\GatewayPeerProjectionManager', $this->peers);
});

it('removes only the target WireGuard peer before reconciling DNS', function (): void {
    $caller = remove_node_record(name: 'operator', wireguardAddress: '10.44.0.2');
    $target = remove_node_record(name: 'retired', wireguardAddress: '10.44.0.3');
    $target->update(['wireguard_public_key' => 'TARGET_PUBLIC_KEY']);

    $this
        ->withServerVariables(['REMOTE_ADDR' => $caller->wireguard_address])
        ->deleteJson("/api/v1/nodes/{$target->id}")
        ->assertOk()
        ->assertJsonPath('data.wireguard_peer_removed', true)
        ->assertJsonPath('data.dns_records_removed', true);

    expect($this->peers->removed)
        ->toBe([$target->id])
        ->and($this->peers->restored)
        ->toBeEmpty()
        ->and($this->dns->convergences)
        ->toBe(1)
        ->and($target->fresh())
        ->toBeNull();
});

it('returns 502 and retains active state when WireGuard projection fails', function (): void {
    $caller = remove_node_record(name: 'operator', wireguardAddress: '10.44.0.2');
    $target = remove_node_record(name: 'retired', wireguardAddress: '10.44.0.3');
    $target->update(['wireguard_public_key' => 'TARGET_PUBLIC_KEY']);
    $this->peers->removeFailure = new RuntimeException('private projection detail');

    $this
        ->withServerVariables(['REMOTE_ADDR' => $caller->wireguard_address])
        ->deleteJson("/api/v1/nodes/{$target->id}")
        ->assertStatus(502)
        ->assertJsonPath('error.code', 'node.wireguard_projection_failed')
        ->assertJsonPath('error.details.step', 'wireguard-projection')
        ->assertJsonMissing(['private projection detail']);

    expect($target->fresh()?->status)
        ->toBe(LifecycleStatus::Active)
        ->and($this->dns->convergences)
        ->toBe(0)
        ->and($this->peers->restored)
        ->toBeEmpty();
});

it('restores the WireGuard peer and node state when DNS projection fails', function (): void {
    $caller = remove_node_record(name: 'operator', wireguardAddress: '10.44.0.2');
    $target = remove_node_record(name: 'retired', wireguardAddress: '10.44.0.3');
    $target->update(['wireguard_public_key' => 'TARGET_PUBLIC_KEY']);
    $this->dns->failure = new RuntimeException('private DNS detail');

    $this
        ->withServerVariables(['REMOTE_ADDR' => $caller->wireguard_address])
        ->deleteJson("/api/v1/nodes/{$target->id}")
        ->assertStatus(502)
        ->assertJsonPath('error.code', 'node.dns_projection_failed')
        ->assertJsonPath('error.details.step', 'dns-projection')
        ->assertJsonMissing(['private DNS detail']);

    expect($target->fresh()?->status)
        ->toBe(LifecycleStatus::Active)
        ->and($this->peers->removed)
        ->toBe([$target->id])
        ->and($this->peers->restored)
        ->toBe([$target->id]);
});

it('returns a stable rollback error when restoring the WireGuard peer fails', function (): void {
    $caller = remove_node_record(name: 'operator', wireguardAddress: '10.44.0.2');
    $target = remove_node_record(name: 'retired', wireguardAddress: '10.44.0.3');
    $target->update(['wireguard_public_key' => 'TARGET_PUBLIC_KEY']);
    $this->dns->failure = new RuntimeException('private DNS detail');
    $this->peers->restoreFailure = new RuntimeException('private rollback detail');

    $this
        ->withServerVariables(['REMOTE_ADDR' => $caller->wireguard_address])
        ->deleteJson("/api/v1/nodes/{$target->id}")
        ->assertStatus(502)
        ->assertJsonPath('error.code', 'node.removal_rollback_failed')
        ->assertJsonPath('error.details.step', 'wireguard-rollback')
        ->assertJsonMissing(['private DNS detail', 'private rollback detail']);

    expect($target->fresh()?->status)
        ->toBe(LifecycleStatus::Active)
        ->and($this->peers->restored)
        ->toBe([$target->id]);
});

it('restores network projections and active state when persistence deletion fails', function (): void {
    $caller = remove_node_record(name: 'operator', wireguardAddress: '10.44.0.2');
    $target = remove_node_record(name: 'persistence-failure', wireguardAddress: '10.44.0.3');
    $target->update(['wireguard_public_key' => 'TARGET_PUBLIC_KEY']);
    Node::deleting(static function (Node $node): void {
        if ($node->name === 'persistence-failure') {
            throw new RuntimeException('private database detail');
        }
    });

    $this
        ->withServerVariables(['REMOTE_ADDR' => $caller->wireguard_address])
        ->deleteJson("/api/v1/nodes/{$target->id}")
        ->assertStatus(502)
        ->assertJsonPath('error.code', 'node.persistence_failed')
        ->assertJsonPath('error.details.step', 'persistence')
        ->assertJsonMissing(['private database detail']);

    expect($target->fresh()?->status)
        ->toBe(LifecycleStatus::Active)
        ->and($this->peers->removed)
        ->toBe([$target->id])
        ->and($this->peers->restored)
        ->toBe([$target->id])
        ->and($this->dns->convergences)
        ->toBe(2);
});

it('removes a roleless node without resources and returns the stable projection result', function (): void {
    $caller = remove_node_record(name: 'operator', wireguardAddress: '10.44.0.2');
    $target = remove_node_record(name: 'retired', wireguardAddress: '10.44.0.3');
    $requestId = '47783d46-e420-42f6-868d-31dadf54105c';

    $response = $this
        ->withHeader('X-Orbit-Request-Id', $requestId)
        ->withServerVariables(['REMOTE_ADDR' => $caller->wireguard_address])
        ->deleteJson("/api/v1/nodes/{$target->id}");

    $response
        ->assertOk()
        ->assertHeader('X-Orbit-Request-Id', $requestId)
        ->assertJsonPath('data.id', $target->id)
        ->assertJsonPath('data.name', 'retired')
        ->assertJsonPath('data.removed', true)
        ->assertJsonPath('data.wireguard_peer_removed', false)
        ->assertJsonPath('data.dns_records_removed', true)
        ->assertJsonPath('meta.request_id', $requestId);

    expect($target->fresh())
        ->toBeNull()
        ->and($this->dns->convergences)
        ->toBe(1);

    $activity = Activity::query()->where('command', 'node:remove')->sole();

    expect($activity->subject_type)
        ->toBe(Node::class)
        ->and($activity->subject_id)
        ->toBe($target->id)
        ->and($activity->target_node_id)
        ->toBeNull()
        ->and($activity->properties?->get('target_node'))
        ->toBe(['id' => $target->id, 'name' => 'retired'])
        ->and($activity->status)
        ->toBe('succeeded');
});

it('returns 409 without side effects when the caller targets itself', function (): void {
    $caller = remove_node_record(name: 'operator', wireguardAddress: '10.44.0.2');

    $this
        ->withServerVariables(['REMOTE_ADDR' => $caller->wireguard_address])
        ->deleteJson("/api/v1/nodes/{$caller->id}")
        ->assertConflict()
        ->assertJsonPath('error.code', 'node.self_removal_forbidden');

    expect($caller->fresh())
        ->not
        ->toBeNull()
        ->and($this->dns->convergences)
        ->toBe(0);
});

it('returns 409 when the target still has any role assignment', function (RoleName $role): void {
    $caller = remove_node_record(name: 'operator', wireguardAddress: '10.44.0.2');
    $target = remove_node_record(name: 'retired', wireguardAddress: '10.44.0.3');
    NodeRole::query()->create([
        'node_id' => $target->id,
        'role' => $role,
        'status' => LifecycleStatus::Active,
    ]);

    $this
        ->withServerVariables(['REMOTE_ADDR' => $caller->wireguard_address])
        ->deleteJson("/api/v1/nodes/{$target->id}")
        ->assertConflict()
        ->assertJsonPath('error.code', match ($role) {
            RoleName::Gateway => 'node.gateway_removal_forbidden',
            RoleName::Vpn => 'node.vpn_removal_forbidden',
            default => 'node.has_roles',
        });

    expect($target->fresh())
        ->not
        ->toBeNull()
        ->and($this->dns->convergences)
        ->toBe(0);
})->with(RoleName::cases());

it('returns 409 when the target still owns an instance', function (): void {
    $caller = remove_node_record(name: 'operator', wireguardAddress: '10.44.0.2');
    $target = remove_node_record(name: 'retired', wireguardAddress: '10.44.0.3');
    $app = OrbitApp::query()->create([
        'name' => 'Acme',
        'slug' => 'acme',
        'repository_url' => 'https://github.com/acme/site.git',
    ]);
    Instance::query()->create([
        'app_id' => $app->id,
        'node_id' => $target->id,
        'name' => 'production',
        'environment' => 'production',
        'checkout_path' => '/var/www/acme/production',
        'hostname' => 'acme.example.com',
        'certificate_mode' => 'acme',
    ]);

    $this
        ->withServerVariables(['REMOTE_ADDR' => $caller->wireguard_address])
        ->deleteJson("/api/v1/nodes/{$target->id}")
        ->assertConflict()
        ->assertJsonPath('error.code', 'node.has_instances');

    expect($target->fresh())
        ->not
        ->toBeNull()
        ->and($this->dns->convergences)
        ->toBe(0);
});

it('returns 409 when the target still owns a firewall rule', function (): void {
    $caller = remove_node_record(name: 'operator', wireguardAddress: '10.44.0.2');
    $target = remove_node_record(name: 'retired', wireguardAddress: '10.44.0.3');
    FirewallRule::query()->create([
        'node_id' => $target->id,
        'name' => 'https',
        'action' => 'allow',
        'source' => 'any',
        'protocol' => 'tcp',
        'port' => '443',
        'status' => LifecycleStatus::Active,
    ]);

    $this
        ->withServerVariables(['REMOTE_ADDR' => $caller->wireguard_address])
        ->deleteJson("/api/v1/nodes/{$target->id}")
        ->assertConflict()
        ->assertJsonPath('error.code', 'node.has_firewall_rules');

    expect($target->fresh())
        ->not
        ->toBeNull()
        ->and($this->dns->convergences)
        ->toBe(0);
});

function remove_node_record(string $name, string $wireguardAddress): Node
{
    return Node::query()->create([
        'name' => $name,
        'status' => LifecycleStatus::Active,
        'platform' => 'linux',
        'public_ssh_host' => str_replace(
            search: '10.44.0.',
            replace: '192.0.2.',
            subject: $wireguardAddress,
        ),
        'public_ssh_port' => 22,
        'ssh_user' => 'orbit',
        'wireguard_address' => $wireguardAddress,
    ]);
}

final class RemoveNodeFakeDnsManager implements PrivateDnsManager
{
    public int $convergences = 0;

    public ?Throwable $failure = null;

    public function converge(?Node $pendingNode = null): void
    {
        $this->convergences++;

        if ($this->failure instanceof Throwable) {
            throw $this->failure;
        }
    }
}

/** @mago-expect lint:single-class-per-file Test-local fakes keep projection state visible to this API suite. */
final class RemoveNodeFakePeerProjection implements GatewayPeerProjectionManager
{
    /** @var list<int> */
    public array $removed = [];

    /** @var list<int> */
    public array $restored = [];

    public ?Throwable $removeFailure = null;

    public ?Throwable $restoreFailure = null;

    public function converge(Node $node): void {}

    public function remove(Node $node): void
    {
        $this->removed[] = $node->id;

        if ($this->removeFailure instanceof Throwable) {
            throw $this->removeFailure;
        }
    }

    public function restore(Node $node): void
    {
        $this->restored[] = $node->id;

        if ($this->restoreFailure instanceof Throwable) {
            throw $this->restoreFailure;
        }
    }
}
