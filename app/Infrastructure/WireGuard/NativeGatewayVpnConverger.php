<?php

declare(strict_types=1);

namespace App\Infrastructure\WireGuard;

use App\Data\Gateway\BootstrapGatewayData;
use App\Domain\Gateway\GatewayVpnConverger;
use App\Domain\Nodes\NodeProvisioningException;
use App\Infrastructure\Files\ProtectedFileWriter;
use App\Infrastructure\Firewall\UfwManagedRule;
use App\Infrastructure\Firewall\UfwRuleOwnership;
use App\Infrastructure\Firewall\UfwRuleShape;
use App\Infrastructure\Firewall\UfwStatusParser;
use App\Infrastructure\Firewall\UfwStoredRuleParser;
use App\Infrastructure\Firewall\UfwStoredRuleProbe;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Processes\ProcessRunner;
use App\Models\Node;
use Closure;

/**
 * @mago-expect lint:cyclomatic-complexity The converger keeps dependent VPN safety gates in execution order.
 * @mago-expect lint:excessive-parameter-list Active and protected stored UFW sources use distinct typed parsers.
 * @mago-expect lint:kan-defect The score reflects explicit rollback and recovery branches at the host boundary.
 * @mago-expect lint:too-many-methods Private methods keep each protected host operation bounded and testable.
 */
final readonly class NativeGatewayVpnConverger implements GatewayVpnConverger
{
    private const string CANDIDATE_CONFIG = '/etc/wireguard/orbit-candidate.conf';

    private const string LIVE_CONFIG = '/etc/wireguard/orbit.conf';

    private const string BACKUP_CONFIG = '/etc/wireguard/.orbit.conf.rollback';

    private const string FORWARDING_CANDIDATE = '/etc/sysctl.d/.90-orbit-wireguard-forwarding.conf.candidate';

    private const string FORWARDING_CONFIG = '/etc/sysctl.d/90-orbit-wireguard-forwarding.conf';

    public function __construct(
        private WireGuardServerConfigRenderer $renderer,
        private ProtectedFileWriter $files,
        private ProcessRunner $processes,
        private UfwStatusParser $firewallParser,
        private string $orbitHome,
        private UfwStoredRuleParser $storedFirewallParser = new UfwStoredRuleParser,
    ) {}

    public function converge(Node $gateway, BootstrapGatewayData $data): void
    {
        $this->withServerProjectionLock(function () use ($gateway, $data): void {
            $this->convergeWireGuard($gateway, $data);
        });
        $this->convergeDns($data);
        $this->convergeFirewall($gateway, $data);
    }

    private function convergeWireGuard(Node $gateway, BootstrapGatewayData $data): void
    {
        $prefixLength = $this->prefixLength($data->wireguardSubnet);
        $privateKey = $this->key('private');
        $publicKey = $this->key('public');
        $configuration = new VpnConfiguration(
            server: $gateway,
            subnet: $data->wireguardSubnet,
            prefixLength: $prefixLength,
            port: $data->wireguardPort,
            endpoint: $data->wireguardEndpoint,
            dnsServer: $data->dnsServer,
            dnsThroughWireGuard: true,
            domain: $data->domain,
            serverAddress: "{$data->wireguardAddress}/{$prefixLength}",
            peerAddress: "{$data->wireguardAddress}/{$prefixLength}",
            serverPrivateKey: $privateKey,
            serverPublicKey: $publicKey,
        );
        $generatedPath = rtrim(string: $this->orbitHome, characters: '/').'/generated/wireguard/orbit.conf';
        $this->files->put(
            $generatedPath,
            $this->renderer->render(
                $configuration,
                Node::query()->whereNotNull('wireguard_public_key')->get(),
            ),
        );
        $generatedForwardingPath =
            rtrim(string: $this->orbitHome, characters: '/').'/generated/wireguard/90-orbit-forwarding.conf';
        $this->files->put($generatedForwardingPath, "net.ipv4.ip_forward=1\n");

        $backupCreated = false;

        try {
            $this->run(
                step: 'wireguard-server-install',
                errorCode: 'vpn.server_config_install_failed',
                arguments: [
                    'sudo',
                    'install',
                    '-D',
                    '-o',
                    'root',
                    '-g',
                    'root',
                    '-m',
                    '0600',
                    '--',
                    $generatedPath,
                    self::CANDIDATE_CONFIG,
                ],
            );
            $this->run(
                step: 'wireguard-server-validate',
                errorCode: 'vpn.server_config_invalid',
                arguments: ['sudo', 'wg-quick', 'strip', self::CANDIDATE_CONFIG],
            );
            $this->run(
                step: 'wireguard-forwarding-install',
                errorCode: 'vpn.forwarding_config_install_failed',
                arguments: [
                    'sudo',
                    'install',
                    '-D',
                    '-o',
                    'root',
                    '-g',
                    'root',
                    '-m',
                    '0644',
                    '--',
                    $generatedForwardingPath,
                    self::FORWARDING_CANDIDATE,
                ],
            );
            $this->run(
                step: 'wireguard-forwarding-apply',
                errorCode: 'vpn.forwarding_config_invalid',
                arguments: ['sudo', 'sysctl', '-p', self::FORWARDING_CANDIDATE],
            );
            $this->backupLiveConfig();
            $backupCreated = true;
            $this->run(
                step: 'wireguard-forwarding-install',
                errorCode: 'vpn.forwarding_config_install_failed',
                arguments: [
                    'sudo',
                    'mv',
                    '-f',
                    '--',
                    self::FORWARDING_CANDIDATE,
                    self::FORWARDING_CONFIG,
                ],
            );
            $this->run(
                step: 'wireguard-server-install',
                errorCode: 'vpn.server_config_install_failed',
                arguments: ['sudo', 'mv', '-f', '--', self::CANDIDATE_CONFIG, self::LIVE_CONFIG],
            );
        } catch (NodeProvisioningException $exception) {
            $this->cleanupCandidate($backupCreated);

            throw $exception;
        }

        $this->activateServerConfig();
    }

    private function withServerProjectionLock(Closure $operation): void
    {
        $directory = rtrim(string: $this->orbitHome, characters: '/').'/locks';

        if (
            ! is_dir($directory)
            && ! mkdir(directory: $directory, permissions: 0o700, recursive: true)
            && ! is_dir($directory)
        ) {
            throw new NodeProvisioningException(
                step: 'wireguard-server-lock',
                errorCode: 'vpn.server_lock_failed',
                message: 'Could not create the gateway WireGuard projection lock directory.',
            );
        }

        chmod(filename: $directory, permissions: 0o700);
        $lockPath = $directory.'/wireguard-server.lock';
        $lock = fopen(filename: $lockPath, mode: 'c+');

        if ($lock === false) {
            throw new NodeProvisioningException(
                step: 'wireguard-server-lock',
                errorCode: 'vpn.server_lock_failed',
                message: 'Could not open the gateway WireGuard projection lock.',
            );
        }

        try {
            if (! flock($lock, LOCK_EX)) {
                throw new NodeProvisioningException(
                    step: 'wireguard-server-lock',
                    errorCode: 'vpn.server_lock_failed',
                    message: 'Could not acquire the gateway WireGuard projection lock.',
                );
            }

            $operation();
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private function convergeDns(BootstrapGatewayData $data): void
    {
        $interfaces = $this->privateInterfaces($data);
        $configuration = implode(PHP_EOL, [
            '# Managed by Orbit.',
            ...array_map(static fn (string $interface): string => "interface={$interface}", $interfaces),
            'bind-dynamic',
            'domain-needed',
            'bogus-priv',
            "local=/{$data->domain}/",
            "host-record={$data->name}.{$data->domain},{$data->wireguardAddress}",
            '',
        ]);
        $generatedPath = rtrim(string: $this->orbitHome, characters: '/').'/generated/dnsmasq/orbit-vpn.conf';
        $this->files->put($generatedPath, $configuration, 0o644);
        $encoded = base64_encode($configuration);
        $this->run(
            step: 'vpn-dns',
            errorCode: 'vpn.dns_config_failed',
            arguments: ['sudo', 'bash', '-seu'],
            input: <<<BASH
                managed=/etc/dnsmasq.d/orbit-vpn.conf
                candidate=/etc/dnsmasq.d/.orbit-vpn.\$\$.candidate
                validation=\$(mktemp -d)
                backup=\$(mktemp /etc/dnsmasq.d/.orbit-vpn.backup.XXXXXX)
                had_managed=0
                trap 'rm -rf -- "\$validation"; rm -f -- "\$candidate" "\$backup"' EXIT
                exec 9>/run/lock/orbit-dnsmasq.lock
                flock -w 30 9
                if [ -f "\$managed" ]; then
                    cp --preserve=mode,ownership -- "\$managed" "\$backup"
                    had_managed=1
                fi
                install -d -m 0755 -- "\$validation/fragments"
                cp -a -- /etc/dnsmasq.d/. "\$validation/fragments/"
                printf '%s' '{$encoded}' | base64 --decode > "\$validation/fragments/orbit-vpn.conf"
                sed "s#/etc/dnsmasq.d#\$validation/fragments#g" /etc/dnsmasq.conf > "\$validation/dnsmasq.conf"
                dnsmasq --test --conf-file="\$validation/dnsmasq.conf"
                if [ -f "\$managed" ] && cmp -s -- "\$validation/fragments/orbit-vpn.conf" "\$managed"; then
                    if systemctl is-active --quiet dnsmasq; then
                        exit 0
                    fi
                    systemctl restart dnsmasq
                    exit 0
                fi
                install -o root -g root -m 0644 -- "\$validation/fragments/orbit-vpn.conf" "\$candidate"
                mv -fT -- "\$candidate" "\$managed"
                if ! systemctl restart dnsmasq; then
                    if [ "\$had_managed" = 1 ]; then
                        install -o root -g root -m 0644 -- "\$backup" "\$managed"
                    else
                        rm -f -- "\$managed"
                    fi
                    systemctl restart dnsmasq || true
                    exit 1
                fi
                BASH,
        );
    }

    private function convergeFirewall(Node $gateway, BootstrapGatewayData $data): void
    {
        [$status, $inactive] = $this->firewallStatus();
        $rules = [$this->recoveryFirewallRule($gateway), ...$this->firewallRules($data)];

        if ($inactive) {
            $stored = $this->storedFirewallRules();
            $this->guardStoredFirewallDrift($stored, $rules);
            $recovery = $rules[0];

            if (
                $this->storedFirewallParser->ownership($stored->stdout, $recovery->shape) === UfwRuleOwnership::Missing
            ) {
                $this->firewallRule($recovery->arguments);
                $stored = $this->storedFirewallRules();
            }

            if ($this->storedFirewallParser->ownership($stored->stdout, $recovery->shape) !== UfwRuleOwnership::Exact) {
                throw new NodeProvisioningException(
                    step: 'vpn-firewall-recovery-probe',
                    errorCode: 'vpn.firewall_recovery_probe_failed',
                    message: 'The exact stored public SSH recovery rule was not present.',
                    result: $stored,
                );
            }

            $this->run(
                step: 'vpn-firewall-enable',
                errorCode: 'vpn.firewall_enable_failed',
                arguments: ['sudo', 'ufw', '--force', 'enable'],
            );
            [$status, $inactive] = $this->firewallStatus();

            if ($inactive) {
                throw new NodeProvisioningException(
                    step: 'vpn-firewall-status',
                    errorCode: 'vpn.firewall_status_invalid',
                    message: 'Gateway UFW remained inactive after it was enabled.',
                    result: $status,
                );
            }
        }

        foreach ($this->missingFirewallRules($status, $rules) as $rule) {
            $this->firewallRule($rule->arguments);
        }

        [$verification, $inactive] = $this->firewallStatus();

        if ($inactive) {
            throw new NodeProvisioningException(
                step: 'vpn-firewall-probe',
                errorCode: 'vpn.firewall_probe_failed',
                message: 'Gateway UFW was inactive after firewall convergence.',
                result: $verification,
            );
        }

        $this->verifyFirewallRules($verification, $rules);
    }

    /** @return array{CommandResult, bool} */
    private function firewallStatus(): array
    {
        $status = $this->run(
            step: 'vpn-firewall-status',
            errorCode: 'vpn.firewall_status_failed',
            arguments: ['sudo', 'ufw', 'status', 'numbered'],
        );
        $inactive = preg_match('/^Status:\s+inactive$/mi', $status->stdout) === 1;

        if (! $inactive && preg_match('/^Status:\s+active$/mi', $status->stdout) !== 1) {
            throw new NodeProvisioningException(
                step: 'vpn-firewall-status',
                errorCode: 'vpn.firewall_status_invalid',
                message: 'Could not determine the gateway UFW status.',
                result: $status,
            );
        }

        return [$status, $inactive];
    }

    private function storedFirewallRules(): CommandResult
    {
        return $this->run(
            step: 'vpn-firewall-recovery-probe',
            errorCode: 'vpn.firewall_recovery_probe_failed',
            arguments: UfwStoredRuleProbe::arguments(),
        );
    }

    /** @param list<UfwManagedRule> $rules */
    private function guardStoredFirewallDrift(CommandResult $stored, array $rules): void
    {
        foreach ($rules as $rule) {
            if ($this->storedFirewallParser->ownership($stored->stdout, $rule->shape) !== UfwRuleOwnership::Drift) {
                continue;
            }

            $this->throwFirewallDrift($rule, $stored);
        }
    }

    /**
     * @param list<UfwManagedRule> $rules
     * @return list<UfwManagedRule>
     */
    private function missingFirewallRules(CommandResult $status, array $rules): array
    {
        $missing = [];

        foreach ($rules as $rule) {
            $ownership = $this->firewallParser->ownership($status->stdout, $rule->shape);

            if ($ownership === UfwRuleOwnership::Drift) {
                $this->throwFirewallDrift($rule, $status);
            }

            if ($ownership !== UfwRuleOwnership::Missing) {
                continue;
            }

            $missing[] = $rule;
        }

        return $missing;
    }

    /** @param list<UfwManagedRule> $rules */
    private function verifyFirewallRules(CommandResult $status, array $rules): void
    {
        foreach ($rules as $rule) {
            if ($this->firewallParser->ownership($status->stdout, $rule->shape) === UfwRuleOwnership::Exact) {
                continue;
            }

            $this->throwFirewallDrift($rule, $status);
        }
    }

    private function throwFirewallDrift(UfwManagedRule $rule, CommandResult $status): never
    {
        throw new NodeProvisioningException(
            step: 'vpn-firewall-probe',
            errorCode: 'vpn.firewall_probe_failed',
            message: "Gateway firewall rule [{$rule->shape->comment}] did not match its managed shape.",
            result: $status,
        );
    }

    private function recoveryFirewallRule(Node $gateway): UfwManagedRule
    {
        $comment = 'orbit:public-ssh-recovery';

        return new UfwManagedRule(
            shape: new UfwRuleShape(
                comment: $comment,
                action: 'allow',
                direction: 'in',
                source: 'any',
                destination: 'any',
                port: (string) $gateway->public_ssh_port,
                protocol: 'tcp',
                inInterface: null,
                outInterface: null,
                family: null,
            ),
            arguments: [
                'sudo',
                'ufw',
                'allow',
                'in',
                'proto',
                'tcp',
                'to',
                'any',
                'port',
                (string) $gateway->public_ssh_port,
                'comment',
                $comment,
            ],
        );
    }

    /** @return list<UfwManagedRule> */
    private function firewallRules(BootstrapGatewayData $data): array
    {
        $rules = [];
        $wireguardComment = 'orbit:vpn-wireguard';
        $rules[] = new UfwManagedRule(
            shape: $this->incomingFirewallShape(
                comment: $wireguardComment,
                protocol: 'udp',
                port: (string) $data->wireguardPort,
            ),
            arguments: [
                'sudo',
                'ufw',
                'allow',
                'in',
                'proto',
                'udp',
                'to',
                'any',
                'port',
                (string) $data->wireguardPort,
                'comment',
                $wireguardComment,
            ],
        );

        foreach ($this->privateInterfaces($data) as $interface) {
            foreach (['udp', 'tcp'] as $protocol) {
                $comment = "orbit:vpn-dns-{$protocol}-{$interface}";
                $rules[] = new UfwManagedRule(
                    shape: $this->incomingFirewallShape(
                        comment: $comment,
                        protocol: $protocol,
                        port: '53',
                        interface: $interface,
                    ),
                    arguments: [
                        'sudo',
                        'ufw',
                        'allow',
                        'in',
                        'on',
                        $interface,
                        'proto',
                        $protocol,
                        'to',
                        'any',
                        'port',
                        '53',
                        'comment',
                        $comment,
                    ],
                );
            }
        }

        $gatewayComment = 'orbit:gateway-https';
        $rules[] = new UfwManagedRule(
            shape: $this->incomingFirewallShape(
                comment: $gatewayComment,
                protocol: 'tcp',
                port: '443',
                interface: 'orbit',
            ),
            arguments: [
                'sudo',
                'ufw',
                'allow',
                'in',
                'on',
                'orbit',
                'proto',
                'tcp',
                'to',
                'any',
                'port',
                '443',
                'comment',
                $gatewayComment,
            ],
        );
        $forwardingComment = 'orbit:vpn-peer-forwarding';
        $rules[] = new UfwManagedRule(
            shape: new UfwRuleShape(
                comment: $forwardingComment,
                action: 'allow',
                direction: 'fwd',
                source: $data->wireguardSubnet,
                destination: $data->wireguardSubnet,
                port: 'any',
                protocol: 'any',
                inInterface: 'orbit',
                outInterface: 'orbit',
                family: 'v4',
            ),
            arguments: [
                'sudo',
                'ufw',
                'route',
                'allow',
                'in',
                'on',
                'orbit',
                'out',
                'on',
                'orbit',
                'from',
                $data->wireguardSubnet,
                'to',
                $data->wireguardSubnet,
                'comment',
                $forwardingComment,
            ],
        );

        return $rules;
    }

    private function incomingFirewallShape(
        string $comment,
        string $protocol,
        string $port,
        ?string $interface = null,
    ): UfwRuleShape {
        return new UfwRuleShape(
            comment: $comment,
            action: 'allow',
            direction: 'in',
            source: 'any',
            destination: 'any',
            port: $port,
            protocol: $protocol,
            inInterface: $interface,
            outInterface: null,
            family: null,
        );
    }

    /** @return non-empty-list<string> */
    private function privateInterfaces(BootstrapGatewayData $data): array
    {
        if ($data->privateInterface === null) {
            return ['orbit'];
        }

        return ['orbit', $data->privateInterface];
    }

    /** @param non-empty-list<string> $arguments */
    private function firewallRule(array $arguments): void
    {
        $this->run(
            step: 'vpn-firewall',
            errorCode: 'vpn.firewall_rule_failed',
            arguments: $arguments,
        );
    }

    private function prefixLength(string $subnet): int
    {
        [$network, $prefix] = array_pad(
            array: explode(separator: '/', string: $subnet, limit: 2),
            length: 2,
            value: null,
        );
        $prefixLength = filter_var($prefix, FILTER_VALIDATE_INT);

        if (
            ! is_string($network)
            || ! is_int($prefixLength)
            || $prefixLength < 8
            || $prefixLength > 30
            || ip2long($network) === false
        ) {
            throw new NodeProvisioningException(
                step: 'wireguard-configuration',
                errorCode: 'vpn.configuration_invalid',
                message: "WireGuard subnet [{$subnet}] is invalid.",
            );
        }

        return $prefixLength;
    }

    private function key(string $name): string
    {
        $path = rtrim(string: $this->orbitHome, characters: '/')."/wireguard/{$name}.key";
        $key = file_get_contents($path);

        if (! is_string($key) || trim($key) === '') {
            throw new NodeProvisioningException(
                step: 'wireguard-configuration',
                errorCode: 'vpn.configuration_invalid',
                message: "WireGuard key [{$path}] is missing.",
            );
        }

        return trim($key);
    }

    private function backupLiveConfig(): void
    {
        $this->run(
            step: 'wireguard-server-install',
            errorCode: 'vpn.server_config_install_failed',
            arguments: ['sudo', 'bash', '-seu'],
            input: <<<'BASH'
                live=/etc/wireguard/orbit.conf
                backup=/etc/wireguard/.orbit.conf.rollback
                rm -f -- "$backup"
                if [ -f "$live" ]; then
                    cp --preserve=mode,ownership -- "$live" "$backup"
                fi
                BASH,
        );
    }

    private function activateServerConfig(): void
    {
        $this->run(
            step: 'wireguard-server-restart',
            errorCode: 'vpn.server_start_failed',
            arguments: ['sudo', 'bash', '-seu'],
            input: <<<'BASH'
                live=/etc/wireguard/orbit.conf
                backup=/etc/wireguard/.orbit.conf.rollback
                restore_previous() {
                    if [ -f "$backup" ]; then
                        mv -fT -- "$backup" "$live"
                        systemctl restart wg-quick@orbit || true
                    else
                        rm -f -- "$live"
                        systemctl stop wg-quick@orbit || true
                    fi
                }
                if ! systemctl enable wg-quick@orbit; then
                    restore_previous
                    exit 1
                fi
                if ! systemctl restart wg-quick@orbit; then
                    restore_previous
                    exit 1
                fi
                rm -f -- "$backup"
                BASH,
        );
    }

    /** @mago-expect lint:no-boolean-flag-parameter The flag selects whether a failed live swap created a backup. */
    private function cleanupCandidate(bool $includeBackup = false): void
    {
        $paths = [
            self::CANDIDATE_CONFIG,
            self::FORWARDING_CANDIDATE,
        ];

        if ($includeBackup) {
            $paths[] = self::BACKUP_CONFIG;
        }

        $this->processes->run(new ProcessInvocation([
            'sudo',
            'rm',
            '-f',
            '--',
            ...$paths,
        ]));
    }

    /** @param non-empty-list<string> $arguments */
    private function run(
        string $step,
        string $errorCode,
        array $arguments,
        ?string $input = null,
    ): CommandResult {
        $result = $this->processes->run(new ProcessInvocation($arguments, timeout: 60.0, input: $input));

        if (! $result->succeeded()) {
            throw new NodeProvisioningException(
                step: $step,
                errorCode: $errorCode,
                message: 'Could not converge the gateway WireGuard service.',
                result: $result,
            );
        }

        return $result;
    }
}
