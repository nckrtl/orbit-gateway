<?php

declare(strict_types=1);

use App\Actions\Firewall\ListFirewallRulesAction;
use App\Actions\Firewall\RemoveFirewallRuleAction;
use App\Actions\Firewall\StoreFirewallRuleAction;
use App\Data\Firewall\StoreFirewallRuleData;
use App\Domain\Firewall\FirewallAction;
use App\Domain\Firewall\FirewallBackendStatus;
use App\Domain\Firewall\FirewallManager;
use App\Domain\Firewall\FirewallOperationException;
use App\Domain\Shared\LifecycleStatus;
use App\Domain\Shared\ResourceOperationException;
use App\Models\FirewallRule;
use App\Models\Node;

it('stores inactive desired intent and retries convergence without duplicating the name', function (): void {
    $manager = new FirewallFakeManager([
        FirewallBackendStatus::Inactive,
        FirewallBackendStatus::Active,
    ]);
    $action = new StoreFirewallRuleAction($manager);
    $node = firewall_action_node();
    $data = firewall_store_data();

    expect(fn (): array => $action->execute($node, $data))
        ->toThrow(function (FirewallOperationException $exception): void {
            expect($exception->errorCode)
                ->toBe('firewall.backend_inactive')
                ->and($exception->step)
                ->toBe('status')
                ->and($exception->status)
                ->toBe(503);
        });

    $this->assertDatabaseHas('firewall_rules', [
        'node_id' => $node->id,
        'name' => 'web',
        'status' => 'failed',
        'failed_step' => 'status',
        'error_code' => 'firewall.backend_inactive',
    ]);

    $second = $action->execute($node, $data);

    expect($second['created'])
        ->toBeFalse()
        ->and($second['backend_status'])
        ->toBe(FirewallBackendStatus::Active)
        ->and(FirewallRule::query()->count())
        ->toBe(1)
        ->and($manager->converged)
        ->toBe(['web', 'web']);

    $this->assertDatabaseHas('firewall_rules', [
        'node_id' => $node->id,
        'name' => 'web',
        'action' => 'allow',
        'source' => '192.0.2.0/24',
        'protocol' => 'tcp',
        'port' => '443',
        'status' => 'active',
        'failed_step' => null,
        'error_code' => null,
    ]);
});

it('rejects same-name desired drift without changing the stored rule or UFW', function (): void {
    $manager = new FirewallFakeManager([FirewallBackendStatus::Active]);
    $action = new StoreFirewallRuleAction($manager);
    $node = firewall_action_node();
    $action->execute($node, firewall_store_data());

    expect(fn (): array => $action->execute($node, firewall_store_data(port: '8443')))
        ->toThrow(ResourceOperationException::class, 'different configuration');

    expect($manager->converged)
        ->toBe(['web'])
        ->and(FirewallRule::query()->sole()->port)
        ->toBe('443');
});

it('rejects public recovery SSH denies before persistence or UFW', function (): void {
    $manager = new FirewallFakeManager([]);
    $action = new StoreFirewallRuleAction($manager);
    $node = firewall_action_node();

    expect(fn (): array => $action->execute(
        $node,
        firewall_store_data(action: FirewallAction::Deny, port: '1:1024'),
    ))
        ->toThrow(ResourceOperationException::class, 'public recovery SSH port');

    expect(FirewallRule::query()->count())
        ->toBe(0)
        ->and($manager->converged)
        ->toBeEmpty();
});

it('keeps the record when removal cannot run while UFW is inactive and removes it on retry', function (): void {
    $manager = new FirewallFakeManager([], [
        FirewallBackendStatus::Inactive,
        FirewallBackendStatus::Absent,
    ]);
    $node = firewall_action_node();
    $rule = firewall_action_rule($node);
    $action = new RemoveFirewallRuleAction($manager);

    expect(fn (): FirewallBackendStatus => $action->execute($rule))
        ->toThrow(function (FirewallOperationException $exception): void {
            expect($exception->errorCode)
                ->toBe('firewall.backend_inactive')
                ->and($exception->status)
                ->toBe(503);
        });

    expect($rule->fresh())
        ->not
        ->toBeNull()
        ->and($rule->fresh()?->status)
        ->toBe(LifecycleStatus::Failed)
        ->and($rule->fresh()?->error_code)
        ->toBe('firewall.backend_inactive');

    $absent = $action->execute($rule->fresh());

    expect($absent)
        ->toBe(FirewallBackendStatus::Absent)
        ->and(FirewallRule::query()->count())
        ->toBe(0)
        ->and($manager->removed)
        ->toBe(['web', 'web']);
});

it('lists only one node rules in stable name order', function (): void {
    $manager = new FirewallFakeManager([]);
    $node = firewall_action_node();
    $other = firewall_action_node(
        name: 'other',
        publicHost: '192.0.2.21',
        wireguardAddress: '10.44.0.4',
    );
    firewall_action_rule(node: $node, name: 'z-last');
    firewall_action_rule(node: $node, name: 'a-first');
    firewall_action_rule(node: $other, name: 'other');

    $rules = new ListFirewallRulesAction()->execute($node);

    expect($rules->pluck('name')->all())->toBe(['a-first', 'z-last']);
});

function firewall_action_node(
    string $name = 'app-dev',
    string $publicHost = '192.0.2.20',
    string $wireguardAddress = '10.44.0.3',
): Node {
    return Node::query()->create([
        'name' => $name,
        'status' => LifecycleStatus::Active,
        'platform' => 'linux',
        'public_ssh_host' => $publicHost,
        'public_ssh_port' => 22,
        'ssh_user' => 'orbit',
        'wireguard_address' => $wireguardAddress,
    ]);
}

function firewall_store_data(
    FirewallAction $action = FirewallAction::Allow,
    string $port = '443',
): StoreFirewallRuleData {
    return new StoreFirewallRuleData(
        name: 'web',
        action: $action,
        source: '192.0.2.0/24',
        protocol: 'tcp',
        port: $port,
    );
}

function firewall_action_rule(Node $node, string $name = 'web'): FirewallRule
{
    return FirewallRule::query()->create([
        'node_id' => $node->id,
        'name' => $name,
        'action' => 'allow',
        'source' => 'any',
        'protocol' => 'tcp',
        'port' => '443',
        'status' => LifecycleStatus::Active,
    ]);
}

/** @mago-expect lint:file-name Test-local fake makes retry order explicit. */
final class FirewallFakeManager implements FirewallManager
{
    /** @var list<string> */
    public array $converged = [];

    /** @var list<string> */
    public array $removed = [];

    /**
     * @param list<FirewallBackendStatus> $convergence
     * @param list<FirewallBackendStatus> $removals
     */
    public function __construct(
        private array $convergence,
        private array $removals = [],
    ) {}

    public function converge(FirewallRule $rule): FirewallBackendStatus
    {
        $this->converged[] = $rule->name;

        return array_shift($this->convergence) ?? throw new RuntimeException('No convergence result remains.');
    }

    public function remove(FirewallRule $rule): FirewallBackendStatus
    {
        $this->removed[] = $rule->name;

        return array_shift($this->removals) ?? throw new RuntimeException('No removal result remains.');
    }
}
