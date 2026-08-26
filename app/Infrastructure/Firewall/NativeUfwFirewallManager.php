<?php

declare(strict_types=1);

namespace App\Infrastructure\Firewall;

use App\Domain\Firewall\FirewallAction;
use App\Domain\Firewall\FirewallBackendStatus;
use App\Domain\Firewall\FirewallManager;
use App\Domain\Firewall\FirewallOperationException;
use App\Domain\Firewall\FirewallPort;
use App\Domain\Firewall\FirewallSource;
use App\Infrastructure\Ssh\KnownHostsStore;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshConnection;
use App\Infrastructure\Ssh\SshExecutor;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Models\FirewallRule;
use App\Models\Node;

/**
 * @mago-expect lint:cyclomatic-complexity UFW reconciliation fails closed at each ownership and recovery gate.
 * @mago-expect lint:kan-defect The score reflects explicit collision, verification, and recovery branches.
 * @mago-expect lint:too-many-methods UFW reconciliation keeps one ownership boundary in one adapter.
 */
final readonly class NativeUfwFirewallManager implements FirewallManager
{
    public function __construct(
        private SshExecutor $ssh,
        private SshKeyProvider $keys,
        private KnownHostsStore $knownHosts,
        private UfwStatusParser $parser,
        private UfwManagedCommentCounter $commentCounter = new UfwManagedCommentCounter,
    ) {}

    public function converge(FirewallRule $rule): FirewallBackendStatus
    {
        $node = $this->eligibleNode($rule);
        $this->guardRecoverySsh($rule, $node);
        $status = $this->status($node);

        if ($status['backend'] === FirewallBackendStatus::Inactive) {
            return FirewallBackendStatus::Inactive;
        }

        $owned = $this->parser->ownedRules($status['output'], $this->comment($rule));
        $this->guardUnsupportedOwnedShape($rule, $status['output'], $owned);
        $this->guardCollision($rule, $owned);

        if ($this->isComplete($rule, $owned)) {
            return FirewallBackendStatus::Active;
        }

        if ($owned !== [] && ! $this->allMatch($rule, $owned)) {
            $this->executeMutation(
                $node,
                $this->deleteObservedArguments($rule, $owned[0]),
                'reconcile',
                'firewall.reconcile_failed',
            );
        }

        $this->executeMutation(
            $node,
            $this->applyArguments($rule),
            'apply',
            'firewall.apply_failed',
        );

        $verification = $this->status($node);
        $verifiedRules = $this->parser->ownedRules($verification['output'], $this->comment($rule));
        $this->guardUnsupportedOwnedShape($rule, $verification['output'], $verifiedRules);
        $this->guardCollision($rule, $verifiedRules);

        if ($verification['backend'] !== FirewallBackendStatus::Active || ! $this->isComplete($rule, $verifiedRules)) {
            throw new FirewallOperationException(
                step: 'verify',
                errorCode: 'firewall.verify_failed',
                message: "Firewall rule [{$rule->name}] did not match after UFW activation.",
            );
        }

        return FirewallBackendStatus::Active;
    }

    public function remove(FirewallRule $rule): FirewallBackendStatus
    {
        $node = $this->eligibleNode($rule);
        $status = $this->status($node);

        if ($status['backend'] === FirewallBackendStatus::Inactive) {
            return FirewallBackendStatus::Inactive;
        }

        $owned = $this->parser->ownedRules($status['output'], $this->comment($rule));
        $this->guardUnsupportedOwnedShape($rule, $status['output'], $owned);

        if ($owned === []) {
            return FirewallBackendStatus::Absent;
        }

        $this->guardCollision($rule, $owned);
        $arguments = $this->allMatch($rule, $owned)
            ? $this->deleteArguments($rule)
            : $this->deleteObservedArguments($rule, $owned[0]);
        $this->executeMutation($node, $arguments, 'remove', 'firewall.remove_failed');
        $verification = $this->status($node);
        $remaining = $this->parser->ownedRules($verification['output'], $this->comment($rule));
        $this->guardUnsupportedOwnedShape($rule, $verification['output'], $remaining);

        if ($remaining !== []) {
            throw new FirewallOperationException(
                step: 'verify-remove',
                errorCode: 'firewall.remove_verify_failed',
                message: "Firewall rule [{$rule->name}] remained after UFW removal.",
            );
        }

        return FirewallBackendStatus::Absent;
    }

    /** @return array{backend: FirewallBackendStatus, output: string} */
    private function status(Node $node): array
    {
        $result = $this->ssh->execute(
            $this->connection($node),
            new RemoteCommand(['sudo', 'ufw', 'status', 'numbered']),
        );

        if (! $result->succeeded()) {
            throw new FirewallOperationException(
                step: 'status',
                errorCode: 'firewall.status_failed',
                message: "Could not inspect UFW on node [{$node->name}].",
                result: $result,
            );
        }

        if (preg_match('/\AStatus:\s+inactive\s*$/mi', $result->stdout) === 1) {
            return ['backend' => FirewallBackendStatus::Inactive, 'output' => $result->stdout];
        }

        if (preg_match('/\AStatus:\s+active\s*$/mi', $result->stdout) !== 1) {
            throw new FirewallOperationException(
                step: 'status',
                errorCode: 'firewall.status_unrecognized',
                message: "UFW returned an unrecognized status on node [{$node->name}].",
                result: $result,
            );
        }

        return ['backend' => FirewallBackendStatus::Active, 'output' => $result->stdout];
    }

    /** @param list<array{action: string, source: string, port: string, protocol: string, family: string}> $owned */
    private function guardCollision(FirewallRule $rule, array $owned): void
    {
        if ($owned === []) {
            return;
        }

        if (count($owned) > 1 && ! $this->allMatch($rule, $owned)) {
            throw new FirewallOperationException(
                step: 'ownership',
                errorCode: 'firewall.rule_collision',
                message: "Firewall rule name [{$rule->name}] identifies conflicting UFW rules.",
            );
        }

        $shapes = [];
        $families = [];

        foreach ($owned as $observed) {
            $shapes[$this->shapeKey($observed)] = true;
            $families[] = $observed['family'];
        }

        $maximumRules = FirewallSource::family($rule->source) === 'both' ? 2 : 1;
        $familyCollision = count(array_unique($families)) !== count($families);

        if (count($shapes) <= 1 && count($owned) <= $maximumRules && ! $familyCollision) {
            return;
        }

        throw new FirewallOperationException(
            step: 'ownership',
            errorCode: 'firewall.rule_collision',
            message: "Firewall rule name [{$rule->name}] identifies conflicting UFW rules.",
        );
    }

    /** @param list<array{action: string, source: string, port: string, protocol: string, family: string}> $owned */
    private function guardUnsupportedOwnedShape(FirewallRule $rule, string $output, array $owned): void
    {
        if (count($owned) === $this->commentCounter->count($output, $this->comment($rule))) {
            return;
        }

        throw new FirewallOperationException(
            step: 'ownership',
            errorCode: 'firewall.rule_collision',
            message: "Firewall rule name [{$rule->name}] identifies conflicting UFW rules.",
        );
    }

    /** @param list<array{action: string, source: string, port: string, protocol: string, family: string}> $owned */
    private function isComplete(FirewallRule $rule, array $owned): bool
    {
        if (! $this->allMatch($rule, $owned)) {
            return false;
        }

        $expectedFamilies = FirewallSource::family($rule->source) === 'both'
            ? ['v4', 'v6']
            : [FirewallSource::family($rule->source)];
        $observedFamilies = array_values(array_unique(array_column($owned, 'family')));
        sort($expectedFamilies);
        sort($observedFamilies);

        return $observedFamilies === $expectedFamilies;
    }

    /** @param list<array{action: string, source: string, port: string, protocol: string, family: string}> $owned */
    private function allMatch(FirewallRule $rule, array $owned): bool
    {
        foreach ($owned as $observed) {
            if (
                $observed['action'] !== $rule->action->value
                || $observed['source'] !== $rule->source
                || $observed['port'] !== $rule->port
                || $observed['protocol'] !== $rule->protocol
            ) {
                return false;
            }
        }

        return $owned !== [];
    }

    /** @param array{action: string, source: string, port: string, protocol: string, family: string} $observed */
    private function shapeKey(array $observed): string
    {
        return implode(':', [
            $observed['action'],
            $observed['source'],
            $observed['port'],
            $observed['protocol'],
        ]);
    }

    /** @return non-empty-list<string> */
    private function applyArguments(FirewallRule $rule): array
    {
        return [
            'sudo',
            'ufw',
            ...($rule->action === FirewallAction::Allow ? ['prepend'] : []),
            $rule->action->value,
            'in',
            'from',
            $rule->source,
            'to',
            'any',
            'port',
            $rule->port,
            'proto',
            $rule->protocol,
            'comment',
            $this->comment($rule),
        ];
    }

    /** @return non-empty-list<string> */
    private function deleteArguments(FirewallRule $rule): array
    {
        return [
            'sudo',
            'ufw',
            'delete',
            $rule->action->value,
            'in',
            'from',
            $rule->source,
            'to',
            'any',
            'port',
            $rule->port,
            'proto',
            $rule->protocol,
            'comment',
            $this->comment($rule),
        ];
    }

    /**
     * @param array{action: string, source: string, port: string, protocol: string, family: string} $observed
     * @return non-empty-list<string>
     */
    private function deleteObservedArguments(FirewallRule $rule, array $observed): array
    {
        $source = match ([$observed['source'], $observed['family']]) {
            ['any', 'v4'] => '0.0.0.0/0',
            ['any', 'v6'] => '::/0',
            default => $observed['source'],
        };

        return [
            'sudo',
            'ufw',
            'delete',
            $observed['action'],
            'in',
            'from',
            $source,
            'to',
            $observed['family'] === 'v6' ? '::/0' : 'any',
            'port',
            $observed['port'],
            'proto',
            $observed['protocol'],
            'comment',
            $this->comment($rule),
        ];
    }

    /** @param non-empty-list<string> $arguments */
    private function executeMutation(
        Node $node,
        array $arguments,
        string $step,
        string $errorCode,
    ): void {
        $result = $this->ssh->execute($this->connection($node), new RemoteCommand($arguments));

        if ($result->succeeded()) {
            return;
        }

        throw new FirewallOperationException(
            step: $step,
            errorCode: $errorCode,
            message: "UFW firewall step [{$step}] failed on node [{$node->name}].",
            result: $result,
        );
    }

    private function guardRecoverySsh(FirewallRule $rule, Node $node): void
    {
        if ($rule->action !== FirewallAction::Deny || ! FirewallPort::contains($rule->port, $node->public_ssh_port)) {
            return;
        }

        throw new FirewallOperationException(
            step: 'recovery-ssh',
            errorCode: 'firewall.public_ssh_deny_forbidden',
            message: "Firewall rule [{$rule->name}] would deny the public recovery SSH port.",
        );
    }

    private function eligibleNode(FirewallRule $rule): Node
    {
        $node = $rule->node;

        if ($node->platform !== 'linux') {
            throw new FirewallOperationException(
                step: 'platform',
                errorCode: 'firewall.platform_unsupported',
                message: 'Firewall rules require a Linux node.',
            );
        }

        return $node;
    }

    private function connection(Node $node): SshConnection
    {
        $host = $node->wireguard_address;

        if (! is_string($host) || $host === '') {
            throw new FirewallOperationException(
                step: 'wireguard-address',
                errorCode: 'firewall.wireguard_address_missing',
                message: "Node [{$node->name}] has no WireGuard address.",
            );
        }

        return new SshConnection(
            host: $host,
            user: 'orbit',
            port: 22,
            identityFile: $this->keys->privateKeyPath(),
            knownHostsFile: $this->knownHosts->path(),
        );
    }

    private function comment(FirewallRule $rule): string
    {
        return "orbit:node:{$rule->node_id}:firewall:{$rule->name}";
    }
}
