<?php

declare(strict_types=1);

namespace App\Infrastructure\Nodes;

use App\Domain\AppDev\AppDevCaddyManager;
use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\Nodes\NodeConverger;
use App\Domain\Nodes\NodeProvisioningException;
use App\Domain\Nodes\RoleName;
use App\Infrastructure\Firewall\UfwManagedRule;
use App\Infrastructure\Firewall\UfwRuleOwnership;
use App\Infrastructure\Firewall\UfwRuleShape;
use App\Infrastructure\Firewall\UfwStatusParser;
use App\Infrastructure\Firewall\UfwStoredRuleParser;
use App\Infrastructure\Firewall\UfwStoredRuleProbe;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Ssh\HostKeyScanner;
use App\Infrastructure\Ssh\KnownHostsStore;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshConnection;
use App\Infrastructure\Ssh\SshExecutor;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Infrastructure\WireGuard\WireGuardPeerConverger;
use App\Models\Node;

/**
 * @mago-expect lint:cyclomatic-complexity Remote host convergence keeps dependent recovery gates in execution order.
 * @mago-expect lint:excessive-parameter-list
 * @mago-expect lint:kan-defect The score reflects explicit host and firewall recovery gates.
 * @mago-expect lint:too-many-methods Narrow methods keep each remote mutation typed and testable.
 */
final readonly class NativeNodeConverger implements NodeConverger
{
    public function __construct(
        private HostKeyScanner $hostKeys,
        private KnownHostsStore $knownHosts,
        private SshKeyProvider $sshKeys,
        private SshExecutor $ssh,
        private NodeBootstrapCommandFactory $bootstrapCommand,
        private WireGuardPeerConverger $wireGuard,
        private AppDevCaddyManager $appDevCaddy,
        private UfwStatusParser $firewallParser = new UfwStatusParser,
        private UfwStoredRuleParser $storedFirewallParser = new UfwStoredRuleParser,
    ) {}

    public function converge(Node $node, ?string $expectedSshHostFingerprint = null): void
    {
        if ($node->platform !== 'linux') {
            throw new NodeProvisioningException(
                step: 'platform',
                errorCode: 'node.platform_unsupported',
                message: "Node platform [{$node->platform}] has no provisioning adapter.",
            );
        }

        $hostKey = $this->hostKeys->scan($node->public_ssh_host, $node->public_ssh_port);

        if (
            $node->ssh_host_fingerprint !== null
            && $node->ssh_host_fingerprint !== $hostKey->fingerprint
        ) {
            throw new NodeProvisioningException(
                step: 'ssh-host-key',
                errorCode: 'node.ssh_host_key_changed',
                message: "The SSH host key changed for node [{$node->name}].",
            );
        }

        if ($node->ssh_host_fingerprint === null && $expectedSshHostFingerprint === null) {
            throw new NodeProvisioningException(
                step: 'ssh-host-key',
                errorCode: 'node.ssh_host_fingerprint_required',
                message: "An expected SSH host fingerprint is required for node [{$node->name}].",
            );
        }

        if (
            $expectedSshHostFingerprint !== null
            && ! hash_equals($expectedSshHostFingerprint, $hostKey->fingerprint)
        ) {
            throw new NodeProvisioningException(
                step: 'ssh-host-key',
                errorCode: 'node.ssh_host_key_mismatch',
                message: "The SSH host fingerprint did not match for node [{$node->name}].",
            );
        }

        $this->knownHosts->put($node->public_ssh_host, $node->public_ssh_port, $hostKey);
        $node->update([
            'ssh_host_key_type' => $hostKey->type,
            'ssh_host_key' => $hostKey->value,
            'ssh_host_fingerprint' => $hostKey->fingerprint,
        ]);

        $bootstrap = $this->ssh->execute(
            $this->connection($node, $node->ssh_user),
            $this->bootstrapCommand->make($node->loadMissing('roles')),
        );

        if (! $bootstrap->succeeded()) {
            throw new NodeProvisioningException(
                step: 'base-host',
                errorCode: 'node.bootstrap_failed',
                message: "Could not bootstrap node [{$node->name}].",
                result: $bootstrap,
            );
        }

        $verification = $this->ssh->execute(
            $this->connection($node, 'orbit'),
            new RemoteCommand(['true']),
        );

        if (! $verification->succeeded()) {
            throw new NodeProvisioningException(
                step: 'orbit-ssh',
                errorCode: 'node.orbit_ssh_failed',
                message: "Could not connect to node [{$node->name}] as orbit.",
                result: $verification,
            );
        }

        if (! is_string($node->wireguard_address)) {
            throw new NodeProvisioningException(
                step: 'wireguard-address',
                errorCode: 'vpn.peer_address_missing',
                message: "Node [{$node->name}] has no WireGuard address.",
            );
        }

        $wireguardAddress = $node->wireguard_address;
        $this->convergeFirewall($node, $wireguardAddress);
        $this->wireGuard->converge($node, $this->connection($node, 'orbit'));
        $this->knownHosts->put($wireguardAddress, 22, $hostKey);
        $privateVerification = $this->ssh->execute(
            $this->connection($node, 'orbit', $wireguardAddress, 22),
            new RemoteCommand(['true']),
        );

        if (! $privateVerification->succeeded()) {
            throw new NodeProvisioningException(
                step: 'wireguard-ssh',
                errorCode: 'vpn.peer_ssh_failed',
                message: "Could not reach node [{$node->name}] through WireGuard.",
                result: $privateVerification,
            );
        }

        if ($node->roles->pluck('role')->contains(RoleName::AppDev)) {
            try {
                $this->appDevCaddy->converge($node);
            } catch (RuntimeConvergenceException $exception) {
                throw new NodeProvisioningException(
                    step: $exception->step,
                    errorCode: $exception->errorCode,
                    message: $exception->getMessage(),
                    previous: $exception,
                    result: $exception->result,
                );
            }
        }

        $node->update(['ssh_user' => 'orbit']);
    }

    private function convergeFirewall(Node $node, string $wireguardAddress): void
    {
        [$status, $inactive] = $this->firewallStatus($node);
        $rules = $this->firewallRules($node, $wireguardAddress);

        if ($inactive) {
            $stored = $this->storedFirewallRules($node);
            $this->guardStoredFirewallDrift($node, $stored, $rules);

            if (
                $this->storedFirewallParser->ownership($stored->stdout, $rules[0]->shape) === UfwRuleOwnership::Missing
            ) {
                $this->applyFirewallRule($node, $rules[0]);
                $stored = $this->storedFirewallRules($node);
            }

            $this->verifyStoredRecoveryRule($node, $stored, $rules[0]);
            $this->enableFirewall($node);
            [$status, $inactive] = $this->firewallStatus($node);

            if ($inactive) {
                throw new NodeProvisioningException(
                    step: 'host-firewall',
                    errorCode: 'node.firewall_convergence_failed',
                    message: "UFW remained inactive after it was enabled on node [{$node->name}].",
                    result: $status,
                );
            }
        }

        foreach ($this->missingFirewallRules($node, $status, $rules) as $rule) {
            $this->applyFirewallRule($node, $rule);
        }

        [$verification, $inactive] = $this->firewallStatus($node);

        if ($inactive) {
            throw new NodeProvisioningException(
                step: 'host-firewall',
                errorCode: 'node.firewall_convergence_failed',
                message: "UFW was inactive after firewall convergence on node [{$node->name}].",
                result: $verification,
            );
        }

        $this->verifyFirewallRules($node, $verification, $rules);
    }

    /** @return array{CommandResult, bool} */
    private function firewallStatus(Node $node): array
    {
        $status = $this->ssh->execute(
            $this->connection($node, 'orbit'),
            new RemoteCommand(['sudo', 'ufw', 'status', 'numbered']),
        );

        if (! $status->succeeded()) {
            $this->throwFirewallFailure($node, 'Could not inspect UFW.', $status);
        }

        $inactive = preg_match('/^Status:\s+inactive$/mi', $status->stdout) === 1;

        if (! $inactive && preg_match('/^Status:\s+active$/mi', $status->stdout) !== 1) {
            $this->throwFirewallFailure($node, 'UFW returned an unrecognized status.', $status);
        }

        return [$status, $inactive];
    }

    /**
     * @param list<UfwManagedRule> $rules
     * @return list<UfwManagedRule>
     */
    private function missingFirewallRules(Node $node, CommandResult $status, array $rules): array
    {
        $missing = [];

        foreach ($rules as $rule) {
            $ownership = $this->firewallParser->ownership($status->stdout, $rule->shape);

            if ($ownership === UfwRuleOwnership::Drift) {
                $this->throwFirewallDrift($node, $rule, $status);
            }

            if ($ownership !== UfwRuleOwnership::Missing) {
                continue;
            }

            $missing[] = $rule;
        }

        return $missing;
    }

    /** @param list<UfwManagedRule> $rules */
    private function verifyFirewallRules(Node $node, CommandResult $status, array $rules): void
    {
        foreach ($rules as $rule) {
            if ($this->firewallParser->ownership($status->stdout, $rule->shape) === UfwRuleOwnership::Exact) {
                continue;
            }

            $this->throwFirewallDrift($node, $rule, $status);
        }
    }

    private function applyFirewallRule(Node $node, UfwManagedRule $rule): void
    {
        $result = $this->ssh->execute(
            $this->connection($node, 'orbit'),
            new RemoteCommand($rule->arguments),
        );

        if (! $result->succeeded()) {
            $this->throwFirewallFailure($node, "Could not apply [{$rule->shape->comment}].", $result);
        }
    }

    private function storedFirewallRules(Node $node): CommandResult
    {
        $result = $this->ssh->execute(
            $this->connection($node, 'orbit'),
            new RemoteCommand(UfwStoredRuleProbe::arguments()),
        );

        if (! $result->succeeded()) {
            $this->throwFirewallFailure($node, 'Could not inspect protected stored UFW rules.', $result);
        }

        return $result;
    }

    /** @param list<UfwManagedRule> $rules */
    private function guardStoredFirewallDrift(Node $node, CommandResult $stored, array $rules): void
    {
        foreach ($rules as $rule) {
            if ($this->storedFirewallParser->ownership($stored->stdout, $rule->shape) !== UfwRuleOwnership::Drift) {
                continue;
            }

            $this->throwFirewallDrift($node, $rule, $stored);
        }
    }

    private function verifyStoredRecoveryRule(
        Node $node,
        CommandResult $stored,
        UfwManagedRule $recovery,
    ): void {
        if ($this->storedFirewallParser->ownership($stored->stdout, $recovery->shape) === UfwRuleOwnership::Exact) {
            return;
        }

        $this->throwFirewallFailure($node, 'Could not verify the exact stored public SSH recovery rule.', $stored);
    }

    private function enableFirewall(Node $node): void
    {
        $result = $this->ssh->execute(
            $this->connection($node, 'orbit'),
            new RemoteCommand(['sudo', 'ufw', '--force', 'enable']),
        );

        if (! $result->succeeded()) {
            $this->throwFirewallFailure($node, 'Could not enable UFW.', $result);
        }
    }

    /** @return non-empty-list<UfwManagedRule> */
    private function firewallRules(Node $node, string $wireguardAddress): array
    {
        $rules = [$this->incomingFirewallRule(
            comment: 'orbit:public-ssh-recovery',
            protocol: 'tcp',
            port: (string) $node->public_ssh_port,
        )];
        $roles = $node->roles->pluck('role');

        if ($roles->contains(RoleName::AppDev)) {
            $rules[] = $this->incomingFirewallRule(
                comment: 'orbit:app-dev-http',
                protocol: 'tcp',
                port: '80',
                destination: $wireguardAddress,
                interface: 'orbit',
            );
            $rules[] = $this->incomingFirewallRule(
                comment: 'orbit:app-dev-https',
                protocol: 'tcp',
                port: '443',
                destination: $wireguardAddress,
                interface: 'orbit',
            );
        }

        if ($roles->contains(RoleName::AppProd)) {
            $rules[] = $this->incomingFirewallRule(
                comment: 'orbit:app-prod-http',
                protocol: 'tcp',
                port: '80',
            );
            $rules[] = $this->incomingFirewallRule(
                comment: 'orbit:app-prod-https',
                protocol: 'tcp',
                port: '443',
            );
        }

        if ($roles->contains(RoleName::Gateway)) {
            $rules[] = $this->incomingFirewallRule(
                comment: 'orbit:gateway-https',
                protocol: 'tcp',
                port: '443',
                destination: $wireguardAddress,
                interface: 'orbit',
            );
        }

        return $rules;
    }

    private function incomingFirewallRule(
        string $comment,
        string $protocol,
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
                protocol: $protocol,
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
                $protocol,
                'to',
                $destination,
                'port',
                $port,
                'comment',
                $comment,
            ],
        );
    }

    private function throwFirewallDrift(Node $node, UfwManagedRule $rule, CommandResult $result): never
    {
        $this->throwFirewallFailure(
            $node,
            "Managed UFW rule [{$rule->shape->comment}] did not match its exact shape.",
            $result,
        );
    }

    private function throwFirewallFailure(Node $node, string $reason, CommandResult $result): never
    {
        throw new NodeProvisioningException(
            step: 'host-firewall',
            errorCode: 'node.firewall_convergence_failed',
            message: "{$reason} Could not preserve recovery access and converge UFW on node [{$node->name}].",
            result: $result,
        );
    }

    private function connection(
        Node $node,
        string $user,
        ?string $host = null,
        ?int $port = null,
    ): SshConnection {
        return new SshConnection(
            host: $host ?? $node->public_ssh_host,
            user: $user,
            port: $port ?? $node->public_ssh_port,
            identityFile: $this->sshKeys->privateKeyPath(),
            knownHostsFile: $this->knownHosts->path(),
        );
    }
}
