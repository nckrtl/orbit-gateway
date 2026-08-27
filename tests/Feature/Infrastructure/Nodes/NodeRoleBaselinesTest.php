<?php

declare(strict_types=1);

use App\Domain\AppDev\AppDevCaddyManager;
use App\Domain\AppDev\PrivateDnsManager;
use App\Domain\AppProd\AppProdCaddyManager;
use App\Domain\Nodes\NodeRoleFirewallManager;
use App\Domain\Nodes\NodeRoleValidationException;
use App\Domain\Nodes\RoleName;
use App\Infrastructure\AppDev\AppDevSshExecutor;
use App\Infrastructure\AppProd\AppProdSshExecutor;
use App\Infrastructure\Nodes\Roles\AppDevRoleBaseline;
use App\Infrastructure\Nodes\Roles\AppProdRoleBaseline;
use App\Infrastructure\Nodes\Roles\GatewayRoleBaseline;
use App\Infrastructure\Nodes\Roles\NativeRoleBaselineConverger;
use App\Infrastructure\Nodes\Roles\NodeRolePrerequisiteCommandFactory;
use App\Infrastructure\Nodes\Roles\VpnRoleBaseline;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Ssh\HostKey;
use App\Infrastructure\Ssh\KnownHostsStore;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshConnection;
use App\Infrastructure\Ssh\SshExecutor;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Models\Node;
use App\Models\NodeRole;

it('converges and removes only app development role-owned infrastructure', function (): void {
    expect(class_exists(AppDevRoleBaseline::class))->toBeTrue();

    $events = [];
    [$node, $assignment] = role_baseline_models(RoleName::AppDev);
    $baseline = app_dev_role_baseline($events);

    $baseline->converge($node, $assignment);
    $baseline->remove($node, $assignment, purgeData: true);

    expect($events)->toBe([
        'ssh:app-dev',
        'caddy:converge',
        'firewall:converge:app-dev',
        "dns:{$node->id}",
        'caddy:remove',
        'firewall:remove:app-dev',
        'dns:none',
    ]);
});

it('converges and removes only app production role-owned infrastructure', function (): void {
    expect(class_exists(AppProdRoleBaseline::class))->toBeTrue();

    $events = [];
    [$node, $assignment] = role_baseline_models(RoleName::AppProd);
    $baseline = app_prod_role_baseline($events);

    $baseline->converge($node, $assignment);
    $baseline->remove($node, $assignment, purgeData: true);

    expect($events)->toBe([
        'ssh:app-prod',
        'caddy:converge',
        'firewall:converge:app-prod',
        'caddy:remove',
        'firewall:remove:app-prod',
    ]);
});

it('keeps gateway and VPN removal protected at the baseline boundary', function (): void {
    expect(class_exists(GatewayRoleBaseline::class))
        ->toBeTrue()
        ->and(class_exists(VpnRoleBaseline::class))
        ->toBeTrue();

    $events = [];
    [$gatewayNode, $gatewayAssignment] = role_baseline_models(RoleName::Gateway, name: 'gateway-role');
    [$vpnNode, $vpnAssignment] = role_baseline_models(RoleName::Vpn, name: 'vpn-role');
    $firewall = baseline_firewall($events);
    $ssh = baseline_ssh($events);
    $gateway = new GatewayRoleBaseline($firewall);
    $vpn = new VpnRoleBaseline(
        new NodeRolePrerequisiteCommandFactory,
        $ssh,
        baseline_keys(),
        baseline_known_hosts(),
        $firewall,
    );

    $gateway->converge($gatewayNode, $gatewayAssignment);
    $vpn->converge($vpnNode, $vpnAssignment);

    expect($events)->toBe(['firewall:converge:gateway', 'ssh:vpn', 'firewall:converge:vpn']);
    expect(fn () => $gateway->remove($gatewayNode, $gatewayAssignment, purgeData: false))
        ->toThrow(NodeRoleValidationException::class);
    expect(fn () => $vpn->remove($vpnNode, $vpnAssignment, purgeData: false))
        ->toThrow(NodeRoleValidationException::class);
    expect($events)->toBe(['firewall:converge:gateway', 'ssh:vpn', 'firewall:converge:vpn']);
});

it('dispatches every assignment to its code-defined baseline', function (): void {
    expect(class_exists(NativeRoleBaselineConverger::class))->toBeTrue();

    $events = [];
    $firewall = baseline_firewall($events);
    $ssh = baseline_ssh($events);
    $dispatcher = new NativeRoleBaselineConverger(
        new GatewayRoleBaseline($firewall),
        new VpnRoleBaseline(
            new NodeRolePrerequisiteCommandFactory,
            $ssh,
            baseline_keys(),
            baseline_known_hosts(),
            $firewall,
        ),
        app_dev_role_baseline($events),
        app_prod_role_baseline($events),
    );

    foreach (RoleName::cases() as $role) {
        [$node, $assignment] = role_baseline_models($role, "dispatch-{$role->value}");
        $dispatcher->converge($node, $assignment);
    }

    expect($events)->toContain(
        'firewall:converge:gateway',
        'ssh:vpn',
        'ssh:app-dev',
        'ssh:app-prod',
    );
});

/** @return array{Node, NodeRole} */
function role_baseline_models(RoleName $role, string $name = 'role-node'): array
{
    $address = '10.44.0.'.(Node::query()->count() + 2);
    $node = Node::query()->create([
        'name' => $name,
        'status' => 'active',
        'platform' => 'linux',
        'public_ssh_host' => '192.0.2.10',
        'public_ssh_port' => 22,
        'ssh_user' => 'orbit',
        'wireguard_address' => $address,
    ]);
    $assignment = $node->roles()->create(['role' => $role, 'status' => 'provisioning']);

    return [$node, $assignment];
}

/** @param list<string> $events */
function app_dev_role_baseline(array &$events): AppDevRoleBaseline
{
    $caddy = new class($events) implements AppDevCaddyManager {
        /** @param list<string> $events */
        public function __construct(
            private array &$events,
        ) {}

        public function converge(Node $node): void
        {
            $this->events[] = 'caddy:converge';
        }

        public function remove(Node $node): void
        {
            $this->events[] = 'caddy:remove';
        }
    };
    $dns = new class($events) implements PrivateDnsManager {
        /** @param list<string> $events */
        public function __construct(
            private array &$events,
        ) {}

        public function converge(?Node $pendingNode = null): void
        {
            $this->events[] = 'dns:'.($pendingNode->id ?? 'none');
        }
    };

    return new AppDevRoleBaseline(
        new NodeRolePrerequisiteCommandFactory,
        new AppDevSshExecutor(baseline_ssh($events), baseline_keys(), baseline_known_hosts()),
        $caddy,
        baseline_firewall($events),
        $dns,
    );
}

/** @param list<string> $events */
function app_prod_role_baseline(array &$events): AppProdRoleBaseline
{
    $caddy = new class($events) implements AppProdCaddyManager {
        /** @param list<string> $events */
        public function __construct(
            private array &$events,
        ) {}

        public function converge(Node $node): void
        {
            $this->events[] = 'caddy:converge';
        }

        public function remove(Node $node): void
        {
            $this->events[] = 'caddy:remove';
        }
    };

    return new AppProdRoleBaseline(
        new NodeRolePrerequisiteCommandFactory,
        new AppProdSshExecutor(baseline_ssh($events), baseline_keys(), baseline_known_hosts()),
        $caddy,
        baseline_firewall($events),
    );
}

/** @param list<string> $events */
function baseline_firewall(array &$events): NodeRoleFirewallManager
{
    return new class($events) implements NodeRoleFirewallManager {
        /** @param list<string> $events */
        public function __construct(
            private array &$events,
        ) {}

        public function convergeBase(Node $node): void
        {
            $this->events[] = 'firewall:base';
        }

        public function converge(Node $node, RoleName $role): void
        {
            $this->events[] = "firewall:converge:{$role->value}";
        }

        public function remove(Node $node, RoleName $role): void
        {
            $this->events[] = "firewall:remove:{$role->value}";
        }
    };
}

/** @param list<string> $events */
function baseline_ssh(array &$events): SshExecutor
{
    return new class($events) implements SshExecutor {
        /** @param list<string> $events */
        public function __construct(
            private array &$events,
        ) {}

        public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
        {
            $this->events[] = 'ssh:'.($command->arguments[4] ?? 'unknown');

            return new CommandResult(0, '', '', 1, false);
        }
    };
}

function baseline_keys(): SshKeyProvider
{
    return new class implements SshKeyProvider {
        public function privateKeyPath(): string
        {
            return '/tmp/orbit-test-key';
        }

        public function publicKey(): string
        {
            return 'ssh-ed25519 TEST';
        }
    };
}

function baseline_known_hosts(): KnownHostsStore
{
    return new class implements KnownHostsStore {
        public function path(): string
        {
            return '/tmp/orbit-known-hosts';
        }

        public function put(string $host, int $port, HostKey $key): void {}
    };
}
