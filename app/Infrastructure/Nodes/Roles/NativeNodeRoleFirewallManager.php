<?php

declare(strict_types=1);

namespace App\Infrastructure\Nodes\Roles;

use App\Domain\Firewall\FirewallOperationException;
use App\Domain\Nodes\NodeRoleFirewallManager;
use App\Domain\Nodes\RoleName;
use App\Infrastructure\Firewall\UfwManagedRule;
use App\Infrastructure\Firewall\UfwRuleOwnership;
use App\Infrastructure\Firewall\UfwRuleShape;
use App\Infrastructure\Firewall\UfwStatusParser;
use App\Infrastructure\Firewall\UfwStoredRuleParser;
use App\Infrastructure\Firewall\UfwStoredRuleProbe;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Ssh\KnownHostsStore;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshConnection;
use App\Infrastructure\Ssh\SshExecutor;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Models\Node;

/**
 * @mago-expect lint:cyclomatic-complexity Exact UFW ownership keeps convergence and deletion fail closed.
 * @mago-expect lint:kan-defect Each branch protects recovery access or rejects ambiguous owned state.
 * @mago-expect lint:too-many-methods Narrow methods keep each UFW mutation independently verifiable.
 */
final readonly class NativeNodeRoleFirewallManager implements NodeRoleFirewallManager
{
    public function __construct(
        private SshExecutor $ssh,
        private SshKeyProvider $keys,
        private KnownHostsStore $knownHosts,
        private UfwStatusParser $statusParser = new UfwStatusParser,
        private UfwStoredRuleParser $storedParser = new UfwStoredRuleParser,
    ) {}

    public function convergeBase(Node $node): void
    {
        $this->convergeRules($node, [$this->publicSshRule($node)], publicConnection: true, enable: true);
    }

    public function converge(Node $node, RoleName $role): void
    {
        $rules = $this->roleRules($node, $role);

        if ($rules === []) {
            return;
        }

        $this->convergeRules($node, $rules, publicConnection: false, enable: false);
    }

    public function remove(Node $node, RoleName $role): void
    {
        $rules = $this->roleRules($node, $role);

        if ($rules === []) {
            return;
        }

        [$status, $inactive] = $this->status($node, publicConnection: false);

        if ($inactive) {
            $this->fail($node, 'UFW is inactive during role-rule removal.', $status);
        }

        $numbers = [];

        foreach ($rules as $rule) {
            $ownership = $this->statusParser->ownership($status->stdout, $rule->shape);

            if ($ownership === UfwRuleOwnership::Drift) {
                $this->drift($node, $rule, $status);
            }

            if ($ownership === UfwRuleOwnership::Missing) {
                continue;
            }

            array_push($numbers, ...$this->ruleNumbers($status->stdout, $rule->shape->comment));
        }

        rsort($numbers, SORT_NUMERIC);

        foreach ($numbers as $number) {
            $result = $this->execute(
                $node,
                new RemoteCommand(['sudo', 'ufw', '--force', 'delete', (string) $number]),
                publicConnection: false,
            );

            if (! $result->succeeded()) {
                $this->fail($node, "Could not delete owned UFW rule [{$number}].", $result);
            }
        }

        [$verification, $inactive] = $this->status($node, publicConnection: false);

        if ($inactive) {
            $this->fail($node, 'UFW became inactive after role-rule removal.', $verification);
        }

        foreach ($rules as $rule) {
            if ($this->statusParser->ownership($verification->stdout, $rule->shape) === UfwRuleOwnership::Missing) {
                continue;
            }

            $this->drift($node, $rule, $verification);
        }
    }

    /**
     * @param non-empty-list<UfwManagedRule> $rules
     * @mago-expect lint:no-boolean-flag-parameter Connection and activation flags keep one exact UFW protocol.
     */
    private function convergeRules(Node $node, array $rules, bool $publicConnection, bool $enable): void
    {
        [$status, $inactive] = $this->status($node, $publicConnection);

        if ($inactive) {
            if (! $enable) {
                $this->fail($node, 'UFW is inactive during role-rule convergence.', $status);
            }

            $stored = $this->storedRules($node);
            $this->guardStoredDrift($node, $stored, $rules);

            if ($this->storedParser->ownership($stored->stdout, $rules[0]->shape) === UfwRuleOwnership::Missing) {
                $this->apply($node, $rules[0], publicConnection: true);
                $stored = $this->storedRules($node);
            }

            if ($this->storedParser->ownership($stored->stdout, $rules[0]->shape) !== UfwRuleOwnership::Exact) {
                $this->fail($node, 'Could not verify the exact stored public SSH recovery rule.', $stored);
            }

            $enabled = $this->execute(
                $node,
                new RemoteCommand(['sudo', 'ufw', '--force', 'enable']),
                publicConnection: true,
            );

            if (! $enabled->succeeded()) {
                $this->fail($node, 'Could not enable UFW.', $enabled);
            }

            [$status, $inactive] = $this->status($node, publicConnection: true);

            if ($inactive) {
                $this->fail($node, 'UFW remained inactive after it was enabled.', $status);
            }
        }

        foreach ($rules as $rule) {
            $ownership = $this->statusParser->ownership($status->stdout, $rule->shape);

            if ($ownership === UfwRuleOwnership::Drift) {
                $this->drift($node, $rule, $status);
            }

            if ($ownership === UfwRuleOwnership::Missing) {
                $this->apply($node, $rule, $publicConnection);
            }
        }

        [$verification, $inactive] = $this->status($node, $publicConnection);

        if ($inactive) {
            $this->fail($node, 'UFW was inactive after convergence.', $verification);
        }

        foreach ($rules as $rule) {
            if ($this->statusParser->ownership($verification->stdout, $rule->shape) === UfwRuleOwnership::Exact) {
                continue;
            }

            $this->drift($node, $rule, $verification);
        }
    }

    /** @return array{CommandResult, bool} */
    private function status(Node $node, bool $publicConnection): array
    {
        $result = $this->execute(
            $node,
            new RemoteCommand(['sudo', 'ufw', 'status', 'numbered']),
            $publicConnection,
        );

        if (! $result->succeeded()) {
            $this->fail($node, 'Could not inspect UFW.', $result);
        }

        $inactive = preg_match('/^Status:\s+inactive$/mi', $result->stdout) === 1;

        if (! $inactive && preg_match('/^Status:\s+active$/mi', $result->stdout) !== 1) {
            $this->fail($node, 'UFW returned an unrecognized status.', $result);
        }

        return [$result, $inactive];
    }

    private function storedRules(Node $node): CommandResult
    {
        $result = $this->execute(
            $node,
            new RemoteCommand(UfwStoredRuleProbe::arguments()),
            publicConnection: true,
        );

        if (! $result->succeeded()) {
            $this->fail($node, 'Could not inspect protected stored UFW rules.', $result);
        }

        return $result;
    }

    /** @param non-empty-list<UfwManagedRule> $rules */
    private function guardStoredDrift(Node $node, CommandResult $stored, array $rules): void
    {
        foreach ($rules as $rule) {
            if ($this->storedParser->ownership($stored->stdout, $rule->shape) !== UfwRuleOwnership::Drift) {
                continue;
            }

            $this->drift($node, $rule, $stored);
        }
    }

    private function apply(Node $node, UfwManagedRule $rule, bool $publicConnection): void
    {
        $result = $this->execute($node, new RemoteCommand($rule->arguments), $publicConnection);

        if (! $result->succeeded()) {
            $this->fail($node, "Could not apply [{$rule->shape->comment}].", $result);
        }
    }

    private function execute(Node $node, RemoteCommand $command, bool $publicConnection): CommandResult
    {
        return $this->ssh->execute($this->connection($node, $publicConnection), $command);
    }

    /** @mago-expect lint:no-boolean-flag-parameter The flag selects the public recovery or private role boundary. */
    private function connection(Node $node, bool $publicConnection): SshConnection
    {
        $host = $publicConnection ? $node->public_ssh_host : $node->wireguard_address;
        $port = $publicConnection ? $node->public_ssh_port : 22;

        if (! is_string($host) || $host === '') {
            throw new FirewallOperationException(
                step: 'host-firewall',
                errorCode: 'node.firewall_convergence_failed',
                message: "Node [{$node->name}] has no reachable firewall address.",
            );
        }

        return new SshConnection(
            host: $host,
            user: 'orbit',
            port: $port,
            identityFile: $this->keys->privateKeyPath(),
            knownHostsFile: $this->knownHosts->path(),
        );
    }

    private function publicSshRule(Node $node): UfwManagedRule
    {
        return $this->incomingRule(
            comment: 'orbit:public-ssh-recovery',
            port: (string) $node->public_ssh_port,
        );
    }

    /** @return list<UfwManagedRule> */
    private function roleRules(Node $node, RoleName $role): array
    {
        return match ($role) {
            RoleName::AppDev => [
                $this->incomingRule(
                    comment: 'orbit:app-dev-http',
                    port: '80',
                    destination: $this->wireguardAddress($node),
                    interface: 'orbit',
                ),
                $this->incomingRule(
                    comment: 'orbit:app-dev-https',
                    port: '443',
                    destination: $this->wireguardAddress($node),
                    interface: 'orbit',
                ),
            ],
            RoleName::AppProd => [
                $this->incomingRule(comment: 'orbit:app-prod-http', port: '80'),
                $this->incomingRule(comment: 'orbit:app-prod-https', port: '443'),
            ],
            RoleName::Gateway => [
                $this->incomingRule(
                    comment: 'orbit:gateway-https',
                    port: '443',
                    destination: $this->wireguardAddress($node),
                    interface: 'orbit',
                ),
            ],
            RoleName::Vpn => [],
        };
    }

    private function wireguardAddress(Node $node): string
    {
        if (is_string($node->wireguard_address) && $node->wireguard_address !== '') {
            return $node->wireguard_address;
        }

        throw new FirewallOperationException(
            step: 'host-firewall',
            errorCode: 'node.firewall_convergence_failed',
            message: "Node [{$node->name}] has no WireGuard address.",
        );
    }

    private function incomingRule(
        string $comment,
        string $port,
        string $destination = 'any',
        ?string $interface = null,
    ): UfwManagedRule {
        $interfaceArguments = $interface === null ? [] : ['on', $interface];

        return new UfwManagedRule(
            shape: new UfwRuleShape(
                comment: $comment,
                action: 'allow',
                direction: 'in',
                source: 'any',
                destination: $destination,
                port: $port,
                protocol: 'tcp',
                inInterface: $interface,
                outInterface: null,
                family: $destination === 'any' ? null : 'v4',
            ),
            arguments: [
                'sudo',
                'ufw',
                'allow',
                'in',
                ...$interfaceArguments,
                'proto',
                'tcp',
                'to',
                $destination,
                'port',
                $port,
                'comment',
                $comment,
            ],
        );
    }

    /** @return list<int> */
    private function ruleNumbers(string $output, string $comment): array
    {
        $numbers = [];

        foreach (explode("\n", $output) as $line) {
            $matches = [];

            if (
                preg_match(
                    '/^\[\s*(\d+)\].*#\s*'.preg_quote(str: $comment, delimiter: '/').'\s*$/',
                    trim($line),
                    $matches,
                ) === 1
            ) {
                $numbers[] = (int) $matches[1];
            }
        }

        return $numbers;
    }

    private function drift(Node $node, UfwManagedRule $rule, CommandResult $result): never
    {
        $this->fail($node, "Managed UFW rule [{$rule->shape->comment}] did not match its exact shape.", $result);
    }

    private function fail(Node $node, string $reason, CommandResult $result): never
    {
        throw new FirewallOperationException(
            step: 'host-firewall',
            errorCode: 'node.firewall_convergence_failed',
            message: "{$reason} Could not preserve recovery access and converge UFW on node [{$node->name}].",
            result: $result,
        );
    }
}
