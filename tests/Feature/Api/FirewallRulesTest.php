<?php

declare(strict_types=1);

use App\Domain\Firewall\FirewallBackendStatus;
use App\Domain\Firewall\FirewallManager;
use App\Domain\Shared\LifecycleStatus;
use App\Models\Activity;
use App\Models\FirewallRule;
use App\Models\Node;

beforeEach(function (): void {
    $this->firewall = new FirewallApiFakeManager;
    app()->instance(FirewallManager::class, $this->firewall);
    $this->node = Node::query()->create([
        'name' => 'app-dev',
        'status' => LifecycleStatus::Active,
        'platform' => 'linux',
        'public_ssh_host' => '192.0.2.20',
        'public_ssh_port' => 22,
        'ssh_user' => 'orbit',
        'wireguard_address' => '10.44.0.3',
    ]);
    $this->withServerVariables(['REMOTE_ADDR' => $this->node->wireguard_address]);
});

it('returns a stable unavailable error and retains failed intent when UFW is inactive', function (): void {
    $this->firewall->convergence = [FirewallBackendStatus::Inactive];

    $response = $this->postJson("/api/v1/nodes/{$this->node->id}/firewall-rules/allow", [
        'name' => 'private-web',
        'source' => '192.0.2.129/24',
        'protocol' => 'tcp',
        'port' => '0443',
    ]);

    $response
        ->assertServiceUnavailable()
        ->assertHeader('X-Orbit-Request-Id')
        ->assertJsonPath('error.code', 'firewall.backend_inactive')
        ->assertJsonPath('error.details.step', 'status');
    $rule = FirewallRule::query()->sole();

    expect($rule->status)
        ->toBe(LifecycleStatus::Failed)
        ->and($rule->failed_step)
        ->toBe('status')
        ->and($rule->error_code)
        ->toBe('firewall.backend_inactive');

    $this->assertDatabaseHas('activity_log', [
        'command' => 'firewall:allow',
        'subject_type' => FirewallRule::class,
        'subject_id' => $rule->id,
        'target_node_id' => $this->node->id,
        'caller_node_id' => $this->node->id,
        'status' => 'failed',
        'error_code' => 'firewall.backend_inactive',
    ]);
});

it('returns 422 for invalid names sources protocols and ports without persistence', function (
    array $payload,
    string $field,
): void {
    $response = $this->postJson("/api/v1/nodes/{$this->node->id}/firewall-rules/allow", [
        'name' => 'private-web',
        'source' => 'any',
        'protocol' => 'tcp',
        'port' => '443',
        ...$payload,
    ]);

    $response
        ->assertUnprocessable()
        ->assertJsonPath('error.code', 'validation.failed');

    expect($response->json('error.details'))
        ->toHaveKey($field)
        ->and(FirewallRule::query()->count())
        ->toBe(0)
        ->and($this->firewall->converged)
        ->toBeEmpty();
})->with([
    'unsafe name' => [['name' => 'Private Web'], 'name'],
    'hostname source' => [['source' => 'example.test'], 'source'],
    'invalid CIDR' => [['source' => '192.0.2.1/33'], 'source'],
    'protocol outside tcp and udp' => [['protocol' => 'sctp'], 'protocol'],
    'zero port' => [['port' => '0'], 'port'],
    'reversed range' => [['port' => '9000:8000'], 'port'],
]);

it('returns 422 before persistence when a deny intersects public recovery SSH', function (): void {
    $this
        ->postJson("/api/v1/nodes/{$this->node->id}/firewall-rules/deny", [
            'name' => 'block-ssh',
            'source' => 'any',
            'protocol' => 'tcp',
            'port' => '1:1024',
        ])
        ->assertUnprocessable()
        ->assertJsonPath('error.code', 'firewall.public_ssh_deny_forbidden');

    expect(FirewallRule::query()->count())->toBe(0);
});

it('lists stable named intent and removes only the selected node rule', function (): void {
    $this->firewall->convergence = [FirewallBackendStatus::Active];
    $this
        ->postJson("/api/v1/nodes/{$this->node->id}/firewall-rules/allow", [
            'name' => 'private-web',
            'source' => 'any',
            'protocol' => 'tcp',
            'port' => '443',
        ])
        ->assertCreated();

    $this
        ->getJson("/api/v1/nodes/{$this->node->id}/firewall-rules")
        ->assertOk()
        ->assertJsonCount(1, 'data')
        ->assertJsonPath('data.0.name', 'private-web')
        ->assertJsonMissingPath('data.0.backend_status');

    $this->firewall->removals = [FirewallBackendStatus::Inactive, FirewallBackendStatus::Absent];
    $this
        ->deleteJson("/api/v1/nodes/{$this->node->id}/firewall-rules/private-web")
        ->assertServiceUnavailable()
        ->assertJsonPath('error.code', 'firewall.backend_inactive')
        ->assertJsonPath('error.details.step', 'status');
    $this->assertDatabaseHas('firewall_rules', [
        'node_id' => $this->node->id,
        'name' => 'private-web',
        'status' => 'failed',
        'error_code' => 'firewall.backend_inactive',
    ]);

    $this
        ->deleteJson("/api/v1/nodes/{$this->node->id}/firewall-rules/private-web")
        ->assertOk()
        ->assertJsonPath('data.backend_status', 'absent');
    $this->assertDatabaseMissing('firewall_rules', ['node_id' => $this->node->id, 'name' => 'private-web']);

    expect(Activity::query()->where('command', 'firewall:remove')->count())->toBe(2);
});

it('returns 404 without exposing a rule that belongs to another node', function (): void {
    $other = Node::query()->create([
        'name' => 'other',
        'status' => LifecycleStatus::Active,
        'platform' => 'linux',
        'public_ssh_host' => '192.0.2.21',
        'public_ssh_port' => 22,
        'ssh_user' => 'orbit',
        'wireguard_address' => '10.44.0.4',
    ]);
    $other
        ->firewallRules()
        ->create([
            'name' => 'private-web',
            'action' => 'allow',
            'source' => 'any',
            'protocol' => 'tcp',
            'port' => '443',
            'status' => LifecycleStatus::Active,
        ]);

    $this
        ->deleteJson("/api/v1/nodes/{$this->node->id}/firewall-rules/private-web")
        ->assertNotFound();

    expect($this->firewall->removed)->toBeEmpty();
});

it('binds identical firewall rule names through the requested node', function (): void {
    $other = Node::query()->create([
        'name' => 'other-identical-name',
        'status' => LifecycleStatus::Active,
        'platform' => 'linux',
        'public_ssh_host' => '192.0.2.22',
        'public_ssh_port' => 22,
        'ssh_user' => 'orbit',
        'wireguard_address' => '10.44.0.5',
    ]);
    $otherRule = $other
        ->firewallRules()
        ->create([
            'name' => 'private-web',
            'action' => 'allow',
            'source' => 'any',
            'protocol' => 'tcp',
            'port' => '443',
            'status' => LifecycleStatus::Active,
        ]);
    $requestedRule = $this->node
        ->firewallRules()
        ->create([
            'name' => 'private-web',
            'action' => 'allow',
            'source' => 'any',
            'protocol' => 'tcp',
            'port' => '443',
            'status' => LifecycleStatus::Active,
        ]);

    $this
        ->deleteJson("/api/v1/nodes/{$this->node->id}/firewall-rules/private-web")
        ->assertOk();

    $this->assertDatabaseHas('firewall_rules', ['id' => $otherRule->id]);
    $this->assertDatabaseMissing('firewall_rules', ['id' => $requestedRule->id]);

    expect($this->firewall->removed)->toBe(['private-web']);
});

/** @mago-expect lint:file-name Test-local fake makes API lifecycle states explicit. */
final class FirewallApiFakeManager implements FirewallManager
{
    /** @var list<FirewallBackendStatus> */
    public array $convergence = [];

    /** @var list<FirewallBackendStatus> */
    public array $removals = [];

    /** @var list<string> */
    public array $converged = [];

    /** @var list<string> */
    public array $removed = [];

    public function converge(FirewallRule $rule): FirewallBackendStatus
    {
        $this->converged[] = $rule->name;

        return array_shift($this->convergence) ?? FirewallBackendStatus::Active;
    }

    public function remove(FirewallRule $rule): FirewallBackendStatus
    {
        $this->removed[] = $rule->name;

        return array_shift($this->removals) ?? FirewallBackendStatus::Absent;
    }
}
