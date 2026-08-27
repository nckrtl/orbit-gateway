<?php

declare(strict_types=1);

use App\Domain\Firewall\FirewallOperationException;
use App\Domain\Nodes\RoleName;
use App\Infrastructure\Nodes\Roles\NativeNodeRoleFirewallManager;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Ssh\KnownHostsStore;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshConnection;
use App\Infrastructure\Ssh\SshExecutor;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Models\Node;

it('preserves public SSH before enabling inactive UFW', function (): void {
    expect(class_exists(NativeNodeRoleFirewallManager::class))->toBeTrue();

    $ssh = new RoleFirewallSshExecutor(active: false);
    $manager = role_firewall_manager($ssh);
    $node = role_firewall_node();

    $manager->convergeBase($node);

    $arguments = array_map(static fn (array $call): array => $call['command']->arguments, $ssh->calls);

    expect($arguments)
        ->toContain(
            ['sudo', 'ufw', 'status', 'numbered'],
            ['sudo', 'ufw', '--force', 'enable'],
            [
                'sudo',
                'ufw',
                'allow',
                'in',
                'proto',
                'tcp',
                'to',
                'any',
                'port',
                '22',
                'comment',
                'orbit:public-ssh-recovery',
            ],
        )
        ->and($ssh->calls[0]['connection']->host)
        ->toBe('192.0.2.10')
        ->and($ssh->comments())
        ->toContain('orbit:public-ssh-recovery');
});

it('converges each exact role-owned firewall intent', function (RoleName $role, array $comments): void {
    expect(class_exists(NativeNodeRoleFirewallManager::class))->toBeTrue();

    $ssh = new RoleFirewallSshExecutor;
    $manager = role_firewall_manager($ssh);

    $manager->converge(role_firewall_node(), $role);

    expect($ssh->comments())->toContain(...$comments);

    if ($comments === []) {
        expect($ssh->calls)->toBeEmpty();

        return;
    }

    expect($ssh->calls[0]['connection']->host)->toBe('10.44.0.2');
})->with([
    'app development' => [RoleName::AppDev, ['orbit:app-dev-http', 'orbit:app-dev-https']],
    'app production' => [RoleName::AppProd, ['orbit:app-prod-http', 'orbit:app-prod-https']],
    'gateway' => [RoleName::Gateway, ['orbit:gateway-https']],
    'VPN has no firewall intent' => [RoleName::Vpn, []],
]);

it('does not reapply exact managed role rules', function (): void {
    expect(class_exists(NativeNodeRoleFirewallManager::class))->toBeTrue();

    $ssh = new RoleFirewallSshExecutor;
    $manager = role_firewall_manager($ssh);
    $node = role_firewall_node();
    $manager->converge($node, RoleName::AppProd);
    $firstMutations = $ssh->mutations();

    $manager->converge($node, RoleName::AppProd);

    expect($ssh->mutations())->toBe($firstMutations);
});

it('removes only exact owned rules in descending number order', function (): void {
    expect(class_exists(NativeNodeRoleFirewallManager::class))->toBeTrue();

    $ssh = new RoleFirewallSshExecutor;
    $manager = role_firewall_manager($ssh);
    $node = role_firewall_node();
    $manager->converge($node, RoleName::AppProd);
    $ssh->calls = [];

    $manager->remove($node, RoleName::AppProd);

    $deletions = array_values(array_filter(
        $ssh->mutations(),
        static fn (array $arguments): bool => (
            array_slice($arguments, offset: 0, length: 4) === ['sudo', 'ufw', '--force', 'delete']
        ),
    ));
    $numbers = array_map(static fn (array $arguments): int => (int) $arguments[4], $deletions);

    expect($numbers)
        ->toBe(collect($numbers)->sortDesc()->values()->all())
        ->and($ssh->comments())
        ->not
        ->toContain('orbit:app-prod-http', 'orbit:app-prod-https')
        ->and($ssh->unrelatedRulePresent)
        ->toBeTrue();
});

it('fails closed without mutation when an owned comment has drifted', function (): void {
    expect(class_exists(NativeNodeRoleFirewallManager::class))->toBeTrue();

    $ssh = new RoleFirewallSshExecutor(driftedComment: 'orbit:app-dev-http');
    $manager = role_firewall_manager($ssh);

    expect(fn () => $manager->converge(role_firewall_node(), RoleName::AppDev))
        ->toThrow(function (FirewallOperationException $exception): void {
            expect($exception->step)
                ->toBe('host-firewall')
                ->and($exception->errorCode)
                ->toBe('node.firewall_convergence_failed');
        });

    expect($ssh->mutations())->toBeEmpty();
});

function role_firewall_node(): Node
{
    return new Node([
        'name' => 'role-node',
        'platform' => 'linux',
        'public_ssh_host' => '192.0.2.10',
        'public_ssh_port' => 22,
        'wireguard_address' => '10.44.0.2',
    ]);
}

function role_firewall_manager(SshExecutor $ssh): NativeNodeRoleFirewallManager
{
    $keys = new class implements SshKeyProvider {
        public function privateKeyPath(): string
        {
            return '/tmp/orbit-test-key';
        }

        public function publicKey(): string
        {
            return 'ssh-ed25519 TEST';
        }
    };
    $knownHosts = new class implements KnownHostsStore {
        public function path(): string
        {
            return '/tmp/orbit-known-hosts';
        }

        public function put(string $host, int $port, \App\Infrastructure\Ssh\HostKey $key): void {}
    };

    return new NativeNodeRoleFirewallManager($ssh, $keys, $knownHosts);
}

/**
 * @mago-expect lint:cyclomatic-complexity The stateful fake models UFW status transitions and mutations.
 * @mago-expect lint:file-name The stateful fake stays with its focused firewall interaction tests.
 * @mago-expect lint:kan-defect Branches simulate the remote UFW protocol for focused interaction tests.
 */
final class RoleFirewallSshExecutor implements SshExecutor
{
    /** @var list<array{connection: SshConnection, command: RemoteCommand}> */
    public array $calls = [];

    public bool $unrelatedRulePresent = true;

    /** @var list<array{comment: string, family: string}> */
    private array $rules = [];

    public function __construct(
        private bool $active = true,
        private readonly ?string $driftedComment = null,
    ) {}

    public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
    {
        $this->calls[] = ['connection' => $connection, 'command' => $command];
        $arguments = $command->arguments;

        if ($arguments === ['sudo', 'ufw', 'status', 'numbered']) {
            return new CommandResult(0, $this->status(), '', 1, false);
        }

        if (array_slice(array: $arguments, offset: 0, length: 2) === ['sudo', 'awk']) {
            return new CommandResult(0, $this->storedRules(), '', 1, false);
        }

        if (array_slice(array: $arguments, offset: 0, length: 3) === ['sudo', 'ufw', 'allow']) {
            $commentIndex = array_search('comment', $arguments, strict: true);
            $comment = is_int($commentIndex) ? $arguments[$commentIndex + 1] ?? null : null;

            if (is_string($comment)) {
                $this->add($comment);
            }
        }

        if ($arguments === ['sudo', 'ufw', '--force', 'enable']) {
            $this->active = true;
        }

        if (array_slice(array: $arguments, offset: 0, length: 4) === ['sudo', 'ufw', '--force', 'delete']) {
            $index = (int) ($arguments[4] ?? 0) - 2;

            if (array_key_exists($index, $this->rules)) {
                array_splice(array: $this->rules, offset: $index, length: 1);
            }
        }

        return new CommandResult(0, '', '', 1, false);
    }

    /** @return list<string> */
    public function comments(): array
    {
        return array_values(array_unique(array_column($this->rules, 'comment')));
    }

    /** @return list<list<string>> */
    public function mutations(): array
    {
        return array_values(array_map(
            static fn (array $call): array => $call['command']->arguments,
            array_filter(
                $this->calls,
                static fn (array $call): bool => (
                    array_slice(array: $call['command']->arguments, offset: 0, length: 2) === ['sudo', 'ufw']
                    && $call['command']->arguments !== ['sudo', 'ufw', 'status', 'numbered']
                ),
            ),
        ));
    }

    private function add(string $comment): void
    {
        $families = in_array(
            $comment,
            [
                'orbit:public-ssh-recovery',
                'orbit:app-prod-http',
                'orbit:app-prod-https',
            ],
            strict: true,
        )
            ? ['v4', 'v6']
            : ['v4'];

        foreach ($families as $family) {
            $this->rules[] = ['comment' => $comment, 'family' => $family];
        }
    }

    private function status(): string
    {
        if (! $this->active) {
            return "Status: inactive\n";
        }

        $lines = ['Status: active', '', '[ 1] 53/udp DENY IN 203.0.113.10 # unrelated'];

        foreach ($this->rules as $offset => $rule) {
            $number = $offset + 2;
            $lines[] = $this->line($number, $rule['comment'], $rule['family']);
        }

        if ($this->driftedComment !== null && ! in_array($this->driftedComment, $this->comments(), strict: true)) {
            $lines[] = '[99] 10.44.0.2 1:65535/tcp on orbit ALLOW IN Anywhere # '.$this->driftedComment;
        }

        return implode("\n", $lines)."\n";
    }

    private function line(int $number, string $comment, string $family): string
    {
        $v6 = $family === 'v6' ? ' (v6)' : '';

        return match ($comment) {
            'orbit:public-ssh-recovery' => "[ {$number}] 22/tcp{$v6} ALLOW IN Anywhere{$v6} # {$comment}",
            'orbit:app-dev-http' => "[ {$number}] 10.44.0.2 80/tcp on orbit ALLOW IN Anywhere # {$comment}",
            'orbit:app-dev-https' => "[ {$number}] 10.44.0.2 443/tcp on orbit ALLOW IN Anywhere # {$comment}",
            'orbit:app-prod-http' => "[ {$number}] 80/tcp{$v6} ALLOW IN Anywhere{$v6} # {$comment}",
            'orbit:app-prod-https' => "[ {$number}] 443/tcp{$v6} ALLOW IN Anywhere{$v6} # {$comment}",
            'orbit:gateway-https' => "[ {$number}] 10.44.0.2 443/tcp on orbit ALLOW IN Anywhere # {$comment}",
            default => throw new LogicException("Unknown test comment [{$comment}]."),
        };
    }

    private function storedRules(): string
    {
        $lines = [];

        foreach ($this->rules as $rule) {
            $comment = $rule['comment'];

            if ($comment !== 'orbit:public-ssh-recovery') {
                continue;
            }

            $endpoint = $rule['family'] === 'v6' ? '::/0' : '0.0.0.0/0';
            $encoded = bin2hex($comment);
            $lines[] = "__orbit_ufw_tuple:{$rule['family']}:### tuple ### allow tcp 22 {$endpoint} any {$endpoint} in comment={$encoded}";
        }

        return implode("\n", $lines);
    }
}
