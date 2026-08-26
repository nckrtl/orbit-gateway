<?php

declare(strict_types=1);

use App\Domain\Firewall\FirewallBackendStatus;
use App\Domain\Firewall\FirewallOperationException;
use App\Infrastructure\Firewall\NativeUfwFirewallManager;
use App\Infrastructure\Firewall\UfwStatusParser;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Ssh\KnownHostsStore;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshConnection;
use App\Infrastructure\Ssh\SshExecutor;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Models\FirewallRule;
use App\Models\Node;

it('stores intent without changing or enabling inactive UFW', function (): void {
    $ssh = new FirewallFakeSshExecutor([
        firewall_command_result("Status: inactive\n"),
    ]);
    $manager = firewall_manager($ssh);

    $status = $manager->converge(firewall_rule());

    expect($status)
        ->toBe(FirewallBackendStatus::Inactive)
        ->and($ssh->arguments)
        ->toBe([['sudo', 'ufw', 'status', 'numbered']]);
});

it('prepends a missing allow rule and verifies both address families', function (): void {
    $ssh = new FirewallFakeSshExecutor([
        firewall_command_result("Status: active\n"),
        firewall_command_result('Rule added'),
        firewall_command_result(firewall_active_status([
            '[ 1] 443/tcp                    ALLOW IN    Anywhere                   # orbit:node:7:firewall:web',
            '[ 2] 443/tcp (v6)               ALLOW IN    Anywhere (v6)              # orbit:node:7:firewall:web',
        ])),
    ]);
    $manager = firewall_manager($ssh);

    $status = $manager->converge(firewall_rule());

    expect($status)
        ->toBe(FirewallBackendStatus::Active)
        ->and($ssh->arguments)
        ->toBe([
            ['sudo', 'ufw', 'status', 'numbered'],
            [
                'sudo',
                'ufw',
                'prepend',
                'allow',
                'in',
                'from',
                'any',
                'to',
                'any',
                'port',
                '443',
                'proto',
                'tcp',
                'comment',
                'orbit:node:7:firewall:web',
            ],
            ['sudo', 'ufw', 'status', 'numbered'],
        ]);
});

it('repairs a missing IPv6 half without deleting the matching IPv4 half', function (): void {
    $ipv4 = '[ 1] 443/tcp                    ALLOW IN    Anywhere                   # orbit:node:7:firewall:web';
    $ssh = new FirewallFakeSshExecutor([
        firewall_command_result(firewall_active_status([$ipv4])),
        firewall_command_result('Rule added (v6)'),
        firewall_command_result(firewall_active_status([
            $ipv4,
            '[ 2] 443/tcp (v6)               ALLOW IN    Anywhere (v6)              # orbit:node:7:firewall:web',
        ])),
    ]);

    firewall_manager($ssh)->converge(firewall_rule());

    expect($ssh->arguments)
        ->toHaveCount(3)
        ->and(array_column($ssh->arguments, 2))
        ->not->toContain('delete');
});

it('reconciles one stale exact managed identity and preserves unrelated same-port rules', function (): void {
    $stale = '[ 1] 443/tcp                    ALLOW IN    192.0.2.0/24              # orbit:node:7:firewall:web';
    $unrelated = '[ 2] 443/tcp                  ALLOW IN    Anywhere                  # operator-owned';
    $ssh = new FirewallFakeSshExecutor([
        firewall_command_result(firewall_active_status([$stale, $unrelated])),
        firewall_command_result('Rule deleted'),
        firewall_command_result('Rule added'),
        firewall_command_result(firewall_active_status([
            $unrelated,
            '[ 2] 443/tcp                    ALLOW IN    Anywhere                   # orbit:node:7:firewall:web',
            '[ 3] 443/tcp (v6)               ALLOW IN    Anywhere (v6)              # orbit:node:7:firewall:web',
        ])),
    ]);

    firewall_manager($ssh)->converge(firewall_rule());

    expect($ssh->arguments[1])
        ->toBe([
            'sudo',
            'ufw',
            'delete',
            'allow',
            'in',
            'from',
            '192.0.2.0/24',
            'to',
            'any',
            'port',
            '443',
            'proto',
            'tcp',
            'comment',
            'orbit:node:7:firewall:web',
        ])
        ->and($ssh->arguments)
        ->not->toContain(['sudo', 'ufw', 'reset']);
});

it('fails closed when one managed name identifies conflicting backend shapes', function (): void {
    $ssh = new FirewallFakeSshExecutor([
        firewall_command_result(firewall_active_status([
            '[ 1] 443/tcp                    ALLOW IN    192.0.2.0/24              # orbit:node:7:firewall:web',
            '[ 2] 8443/tcp                   ALLOW IN    198.51.100.0/24           # orbit:node:7:firewall:web',
        ])),
    ]);

    expect(fn (): FirewallBackendStatus => firewall_manager($ssh)->converge(firewall_rule()))
        ->toThrow(FirewallOperationException::class, 'identifies conflicting UFW rules');

    expect($ssh->arguments)->toHaveCount(1);
});

it('fails closed before mutation when both address families share one stale managed shape', function (): void {
    $ssh = new FirewallFakeSshExecutor([
        firewall_command_result(firewall_active_status([
            '[ 1] 443/tcp                    ALLOW IN    192.0.2.0/24              # orbit:node:7:firewall:web',
            '[ 2] 443/tcp (v6)               ALLOW IN    192.0.2.0/24              # orbit:node:7:firewall:web',
        ])),
    ]);

    expect(fn (): FirewallBackendStatus => firewall_manager($ssh)->converge(firewall_rule()))
        ->toThrow(FirewallOperationException::class, 'identifies conflicting UFW rules');

    expect($ssh->arguments)->toBe([['sudo', 'ufw', 'status', 'numbered']]);
});

it('fails closed when a managed comment identifies an unsupported interface shape', function (): void {
    $status = firewall_active_status([
        '[ 1] 443/tcp                    ALLOW IN    Anywhere                   # orbit:node:7:firewall:web',
        '[ 2] 443/tcp (v6) on orbit      ALLOW IN    Anywhere (v6)              # orbit:node:7:firewall:web',
    ]);
    $ssh = new FirewallFakeSshExecutor([
        firewall_command_result($status),
        firewall_command_result('Rule added'),
        firewall_command_result($status),
    ]);

    expect(fn (): FirewallBackendStatus => firewall_manager($ssh)->converge(firewall_rule()))
        ->toThrow(FirewallOperationException::class, 'identifies conflicting UFW rules');

    expect($ssh->arguments)->toBe([['sudo', 'ufw', 'status', 'numbered']]);
});

it('rejects a deny rule that intersects the public recovery SSH port before SSH', function (): void {
    $ssh = new FirewallFakeSshExecutor([]);
    $rule = firewall_rule([
        'action' => 'deny',
        'port' => '1:1024',
    ]);

    expect(fn (): FirewallBackendStatus => firewall_manager($ssh)->converge($rule))
        ->toThrow(FirewallOperationException::class, 'public recovery SSH port');

    expect($ssh->arguments)->toBeEmpty();
});

it('removes only the exact managed rule and retains desired state while UFW is inactive', function (): void {
    $inactiveSsh = new FirewallFakeSshExecutor([
        firewall_command_result("Status: inactive\n"),
    ]);

    expect(firewall_manager($inactiveSsh)->remove(firewall_rule()))
        ->toBe(FirewallBackendStatus::Inactive);

    $ssh = new FirewallFakeSshExecutor([
        firewall_command_result(firewall_active_status([
            '[ 1] 443/tcp                    ALLOW IN    Anywhere                   # orbit:node:7:firewall:web',
            '[ 2] 443/tcp (v6)               ALLOW IN    Anywhere (v6)              # orbit:node:7:firewall:web',
            '[ 3] 443/tcp                    ALLOW IN    Anywhere                   # operator-owned',
        ])),
        firewall_command_result('Rules deleted'),
        firewall_command_result(firewall_active_status([
            '[ 1] 443/tcp                    ALLOW IN    Anywhere                   # operator-owned',
        ])),
    ]);

    expect(firewall_manager($ssh)->remove(firewall_rule()))
        ->toBe(FirewallBackendStatus::Absent)
        ->and($ssh->arguments[1])
        ->toContain('orbit:node:7:firewall:web')
        ->not->toContain('operator-owned');
});

/** @param array<string, mixed> $attributes */
function firewall_rule(array $attributes = []): FirewallRule
{
    $node = new Node([
        'name' => 'app-dev',
        'platform' => 'linux',
        'public_ssh_host' => '192.0.2.20',
        'public_ssh_port' => 22,
        'ssh_user' => 'orbit',
        'wireguard_address' => '10.44.0.3',
    ]);
    $node->id = 7;
    $rule = new FirewallRule([
        'node_id' => 7,
        'name' => 'web',
        'action' => 'allow',
        'source' => 'any',
        'protocol' => 'tcp',
        'port' => '443',
        ...$attributes,
    ]);
    $rule->id = 11;
    $rule->setRelation('node', $node);

    return $rule;
}

function firewall_manager(FirewallFakeSshExecutor $ssh): NativeUfwFirewallManager
{
    return new NativeUfwFirewallManager(
        ssh: $ssh,
        keys: new FirewallFakeSshKeys,
        knownHosts: new FirewallFakeKnownHosts,
        parser: new UfwStatusParser,
    );
}

function firewall_command_result(string $stdout, int $exitCode = 0, string $stderr = ''): CommandResult
{
    return new CommandResult($exitCode, $stdout, $stderr, 1, false);
}

/** @param list<string> $rules */
function firewall_active_status(array $rules): string
{
    return "Status: active\n\nTo Action From\n".implode("\n", $rules)."\n";
}

final class FirewallFakeSshExecutor implements SshExecutor
{
    /** @var list<list<string>> */
    public array $arguments = [];

    /** @param list<CommandResult> $results */
    public function __construct(
        private array $results,
    ) {}

    public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
    {
        $this->arguments[] = $command->arguments;

        return array_shift($this->results) ?? throw new RuntimeException('No fake SSH result remains.');
    }
}

/** @mago-expect lint:single-class-per-file Test-local fake keeps filesystem isolation explicit. */
final readonly class FirewallFakeSshKeys implements SshKeyProvider
{
    public function privateKeyPath(): string
    {
        return '/tmp/orbit-firewall-key';
    }

    public function publicKey(): string
    {
        return 'ssh-ed25519 test';
    }
}

/** @mago-expect lint:single-class-per-file Test-local fake keeps filesystem isolation explicit. */
final readonly class FirewallFakeKnownHosts implements KnownHostsStore
{
    public function put(string $host, int $port, \App\Infrastructure\Ssh\HostKey $hostKey): void {}

    public function path(): string
    {
        return '/tmp/orbit-firewall-known-hosts';
    }
}
