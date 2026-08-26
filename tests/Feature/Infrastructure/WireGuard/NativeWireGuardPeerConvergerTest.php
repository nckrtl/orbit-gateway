<?php

declare(strict_types=1);

use App\Domain\Nodes\NodeProvisioningException;
use App\Domain\Nodes\RoleName;
use App\Domain\Settings\SettingRepository;
use App\Domain\WireGuard\VpnSettings;
use App\Infrastructure\Files\ProtectedFileWriter;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Processes\ProcessRunner;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshConnection;
use App\Infrastructure\Ssh\SshExecutor;
use App\Infrastructure\WireGuard\NativeGatewayPeerProjectionManager;
use App\Infrastructure\WireGuard\NativeWireGuardPeerConverger;
use App\Infrastructure\WireGuard\VpnConfigurationRepository;
use App\Infrastructure\WireGuard\WireGuardServerConfigRenderer;
use App\Models\Node;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;

/** @mago-expect lint:halstead This end-to-end interaction test keeps the command ordering in one observable flow. */
it('validates a candidate config under /etc/wireguard before replacing the live server config', function (): void {
    $orbitHome = sys_get_temp_dir().'/orbit-vpn-'.Str::uuid();
    mkdir(directory: $orbitHome.'/wireguard', permissions: 0o700, recursive: true);
    file_put_contents(
        filename: $orbitHome.'/wireguard/private.key',
        data: str_repeat(string: 'S', times: 43).'=',
    );
    file_put_contents(
        filename: $orbitHome.'/wireguard/public.key',
        data: str_repeat(string: 'P', times: 43).'=',
    );

    try {
        $gateway = Node::query()->create([
            'name' => 'gateway',
            'public_ssh_host' => '85.9.218.89',
            'wireguard_address' => '10.44.0.1',
            'wireguard_public_key' => str_repeat(string: 'P', times: 43).'=',
        ]);
        $gateway->roles()->create(['role' => RoleName::Vpn]);
        $peer = Node::query()->create([
            'name' => 'app-dev',
            'public_ssh_host' => '94.237.40.75',
            'wireguard_address' => '10.44.0.2',
        ]);
        $settings = new VpnSettings(app(SettingRepository::class));
        $settings->configure(
            subnet: '10.44.0.0/24',
            endpoint: '10.0.0.2:51820',
            dnsServer: '10.0.0.2',
        );

        $processes = new class implements ProcessRunner {
            /** @var list<ProcessInvocation> */
            public array $calls = [];

            public function run(ProcessInvocation $invocation): CommandResult
            {
                $this->calls[] = $invocation;

                return new CommandResult(0, '', '', 2, false);
            }
        };
        $ssh = new class implements SshExecutor {
            /** @var list<RemoteCommand> */
            public array $commands = [];

            public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
            {
                $this->commands[] = $command;

                return new CommandResult(0, str_repeat(string: 'A', times: 43)."=\n", '', 2, false);
            }
        };
        $converger = new NativeWireGuardPeerConverger(
            configuration: new VpnConfigurationRepository($settings, $orbitHome),
            gatewayPeers: new NativeGatewayPeerProjectionManager(
                configuration: new VpnConfigurationRepository($settings, $orbitHome),
                serverRenderer: new WireGuardServerConfigRenderer,
                files: new ProtectedFileWriter,
                processes: $processes,
                orbitHome: $orbitHome,
            ),
            ssh: $ssh,
        );

        $converger->converge($peer, new SshConnection(
            host: '94.237.40.75',
            user: 'orbit',
            port: 22,
            identityFile: '/tmp/key',
            knownHostsFile: '/tmp/known_hosts',
        ));

        expect($peer->refresh()->wireguard_public_key)
            ->toBe(str_repeat(string: 'A', times: 43).'=')
            ->and($processes->calls)
            ->toHaveCount(5)
            ->and($processes->calls[0]->arguments)
            ->toBe([
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
                $orbitHome.'/generated/wireguard/orbit.conf',
                '/etc/wireguard/orbit-candidate.conf',
            ])
            ->and($processes->calls[1]->arguments)
            ->toBe([
                'sudo',
                'wg-quick',
                'strip',
                '/etc/wireguard/orbit-candidate.conf',
            ])
            ->and($processes->calls[2]->arguments)
            ->toBe(['sudo', 'bash', '-seu'])
            ->and($processes->calls[2]->input)
            ->toContain('cp --preserve=mode,ownership -- "$live" "$backup"')
            ->and($processes->calls[3]->arguments)
            ->toBe([
                'sudo',
                'mv',
                '-f',
                '--',
                '/etc/wireguard/orbit-candidate.conf',
                '/etc/wireguard/orbit.conf',
            ])
            ->and($processes->calls[4]->arguments)
            ->toBe(['sudo', 'bash', '-seu'])
            ->and($processes->calls[4]->input)
            ->toContain(
                'if ! systemctl restart wg-quick@orbit; then',
                'mv -fT -- "$backup" "$live"',
                'systemctl restart wg-quick@orbit || true',
            )
            ->and($ssh->commands)
            ->toHaveCount(2)
            ->and(file_get_contents($orbitHome.'/generated/wireguard/orbit.conf'))
            ->toContain('AllowedIPs = 10.44.0.2/32');

        expect($ssh->commands[1]->input)
            ->toContain(
                'candidate=/etc/wireguard/orbit-candidate.conf',
                'exec 9>/run/lock/orbit-wireguard-peer.lock',
                'flock -w 30 9',
                'wg-quick strip "$candidate" >/dev/null',
                'mv -f -- "$candidate" "$live"',
                'cp --preserve=mode,ownership -- "$live" "$backup"',
                'mv -fT -- "$backup" "$live"',
                'systemctl restart wg-quick@orbit || true',
                'printf -v dns_server_escaped \'%q\' "$dns_server"',
                'printf -v domain_escaped \'%q\' "~$domain"',
                'dns_mode=$7',
                'dns_state=/etc/wireguard/orbit.dns-link',
                'restore_dns() {',
                'if [ "$dns_mode" = wireguard ]; then',
                'PostUp = resolvectl dns %i $dns_server_escaped; resolvectl domain %i $domain_escaped',
                'PreDown = resolvectl revert %i',
                'route=$(ip -o route get "$dns_server")',
                'if [[ "$route" =~ [[:space:]]dev[[:space:]]([^[:space:]]+) ]]; then',
                'Could not resolve DNS interface.',
                'resolvectl dns "$dns_link" "$dns_server"',
                'resolvectl domain "$dns_link" "~$domain"',
                'printf \'%s\\n%s\\n%s\\n\' "$dns_link" "$dns_server" "$domain" > "$dns_state_candidate"',
            )
            ->not->toContain(
                'candidate=$(mktemp)',
                'PostUp = route=',
                'PreDown = route=',
                '| sed ',
            );

        expect(array_slice($ssh->commands[1]->arguments, -1))
            ->toBe(['underlay']);

        $remoteScript = $ssh->commands[1]->input ?? '';
        $dnsStateWrite = mb_strpos(
            haystack: $remoteScript,
            needle: 'printf \'%s\\n%s\\n%s\\n\' "$dns_link" "$dns_server" "$domain" > "$dns_state_candidate"',
        );
        $backupRemoval = mb_strrpos(haystack: $remoteScript, needle: 'rm -f -- "$backup"');

        expect($dnsStateWrite)
            ->toBeInt()
            ->and($backupRemoval)
            ->toBeInt()
            ->and($dnsStateWrite)
            ->toBeLessThan($backupRemoval);
    } finally {
        new Filesystem()->deleteDirectory($orbitHome);
    }
});

it('does not replace or restart the live service when candidate validation fails', function (): void {
    $orbitHome = sys_get_temp_dir().'/orbit-vpn-'.Str::uuid();
    mkdir(directory: $orbitHome.'/wireguard', permissions: 0o700, recursive: true);
    file_put_contents(
        filename: $orbitHome.'/wireguard/private.key',
        data: str_repeat(string: 'S', times: 43).'=',
    );
    file_put_contents(
        filename: $orbitHome.'/wireguard/public.key',
        data: str_repeat(string: 'P', times: 43).'=',
    );

    try {
        $gateway = Node::query()->create([
            'name' => 'gateway',
            'public_ssh_host' => '85.9.218.89',
            'wireguard_address' => '10.44.0.1',
            'wireguard_public_key' => str_repeat(string: 'P', times: 43).'=',
        ]);
        $gateway->roles()->create(['role' => RoleName::Vpn]);
        $peer = Node::query()->create([
            'name' => 'app-dev',
            'public_ssh_host' => '94.237.40.75',
            'wireguard_address' => '10.44.0.2',
        ]);
        $settings = new VpnSettings(app(SettingRepository::class));
        $settings->configure(
            subnet: '10.44.0.0/24',
            endpoint: '10.0.0.2:51820',
            dnsServer: '10.0.0.2',
        );

        $processes = new class implements ProcessRunner {
            /** @var list<ProcessInvocation> */
            public array $calls = [];

            public function run(ProcessInvocation $invocation): CommandResult
            {
                $this->calls[] = $invocation;

                if (
                    $invocation->arguments === [
                        'sudo',
                        'wg-quick',
                        'strip',
                        '/etc/wireguard/orbit-candidate.conf',
                    ]
                ) {
                    return new CommandResult(1, '', 'Permission denied', 2, false);
                }

                return new CommandResult(0, '', '', 2, false);
            }
        };
        $ssh = new class implements SshExecutor {
            /** @var list<RemoteCommand> */
            public array $commands = [];

            public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
            {
                $this->commands[] = $command;

                return new CommandResult(0, str_repeat(string: 'A', times: 43)."=\n", '', 2, false);
            }
        };
        $converger = new NativeWireGuardPeerConverger(
            configuration: new VpnConfigurationRepository($settings, $orbitHome),
            gatewayPeers: new NativeGatewayPeerProjectionManager(
                configuration: new VpnConfigurationRepository($settings, $orbitHome),
                serverRenderer: new WireGuardServerConfigRenderer,
                files: new ProtectedFileWriter,
                processes: $processes,
                orbitHome: $orbitHome,
            ),
            ssh: $ssh,
        );

        expect(fn () => $converger->converge($peer, new SshConnection(
            host: '94.237.40.75',
            user: 'orbit',
            port: 22,
            identityFile: '/tmp/key',
            knownHostsFile: '/tmp/known_hosts',
        )))
            ->toThrow(function (NodeProvisioningException $exception): void {
                expect($exception->step)
                    ->toBe('wireguard-server-validate')
                    ->and($exception->errorCode)
                    ->toBe('vpn.server_config_invalid');
            });

        expect($processes->calls)
            ->toHaveCount(3)
            ->and($processes->calls[0]->arguments[11])
            ->toBe('/etc/wireguard/orbit-candidate.conf')
            ->and($processes->calls[1]->arguments)
            ->toBe([
                'sudo',
                'wg-quick',
                'strip',
                '/etc/wireguard/orbit-candidate.conf',
            ])
            ->and($processes->calls[2]->arguments)
            ->toBe([
                'sudo',
                'rm',
                '-f',
                '--',
                '/etc/wireguard/orbit-candidate.conf',
            ])
            ->and($ssh->commands)
            ->toHaveCount(1)
            ->and($peer->refresh()->wireguard_public_key)
            ->toBe(str_repeat(string: 'A', times: 43).'=');
    } finally {
        new Filesystem()->deleteDirectory($orbitHome);
    }
});

it('attempts candidate cleanup and preserves the original failure when atomic replace fails', function (): void {
    $orbitHome = sys_get_temp_dir().'/orbit-vpn-'.Str::uuid();
    mkdir(directory: $orbitHome.'/wireguard', permissions: 0o700, recursive: true);
    file_put_contents(
        filename: $orbitHome.'/wireguard/private.key',
        data: str_repeat(string: 'S', times: 43).'=',
    );
    file_put_contents(
        filename: $orbitHome.'/wireguard/public.key',
        data: str_repeat(string: 'P', times: 43).'=',
    );

    try {
        $gateway = Node::query()->create([
            'name' => 'gateway',
            'public_ssh_host' => '85.9.218.89',
            'wireguard_address' => '10.44.0.1',
            'wireguard_public_key' => str_repeat(string: 'P', times: 43).'=',
        ]);
        $gateway->roles()->create(['role' => RoleName::Vpn]);
        $peer = Node::query()->create([
            'name' => 'app-dev',
            'public_ssh_host' => '94.237.40.75',
            'wireguard_address' => '10.44.0.2',
        ]);
        $settings = new VpnSettings(app(SettingRepository::class));
        $settings->configure(
            subnet: '10.44.0.0/24',
            endpoint: '10.0.0.2:51820',
            dnsServer: '10.0.0.2',
        );

        $processes = new class implements ProcessRunner {
            /** @var list<ProcessInvocation> */
            public array $calls = [];

            public function run(ProcessInvocation $invocation): CommandResult
            {
                $this->calls[] = $invocation;

                if (
                    $invocation->arguments === [
                        'sudo',
                        'mv',
                        '-f',
                        '--',
                        '/etc/wireguard/orbit-candidate.conf',
                        '/etc/wireguard/orbit.conf',
                    ]
                ) {
                    return new CommandResult(1, '', 'Device or resource busy', 2, false);
                }

                if (
                    $invocation->arguments === [
                        'sudo',
                        'rm',
                        '-f',
                        '--',
                        '/etc/wireguard/orbit-candidate.conf',
                        '/etc/wireguard/.orbit.conf.rollback',
                    ]
                ) {
                    return new CommandResult(1, '', 'Permission denied', 2, false);
                }

                return new CommandResult(0, '', '', 2, false);
            }
        };
        $ssh = new class implements SshExecutor {
            /** @var list<RemoteCommand> */
            public array $commands = [];

            public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
            {
                $this->commands[] = $command;

                return new CommandResult(0, str_repeat(string: 'A', times: 43)."=\n", '', 2, false);
            }
        };
        $converger = new NativeWireGuardPeerConverger(
            configuration: new VpnConfigurationRepository($settings, $orbitHome),
            gatewayPeers: new NativeGatewayPeerProjectionManager(
                configuration: new VpnConfigurationRepository($settings, $orbitHome),
                serverRenderer: new WireGuardServerConfigRenderer,
                files: new ProtectedFileWriter,
                processes: $processes,
                orbitHome: $orbitHome,
            ),
            ssh: $ssh,
        );

        expect(fn () => $converger->converge($peer, new SshConnection(
            host: '94.237.40.75',
            user: 'orbit',
            port: 22,
            identityFile: '/tmp/key',
            knownHostsFile: '/tmp/known_hosts',
        )))
            ->toThrow(function (NodeProvisioningException $exception): void {
                expect($exception->step)
                    ->toBe('wireguard-server-install')
                    ->and($exception->errorCode)
                    ->toBe('vpn.server_config_install_failed')
                    ->and($exception->result?->stderr)
                    ->toBe('Device or resource busy');
            });

        expect($processes->calls)
            ->toHaveCount(5)
            ->and($processes->calls[1]->arguments)
            ->toBe([
                'sudo',
                'wg-quick',
                'strip',
                '/etc/wireguard/orbit-candidate.conf',
            ])
            ->and($processes->calls[2]->arguments)
            ->toBe(['sudo', 'bash', '-seu'])
            ->and($processes->calls[3]->arguments)
            ->toBe([
                'sudo',
                'mv',
                '-f',
                '--',
                '/etc/wireguard/orbit-candidate.conf',
                '/etc/wireguard/orbit.conf',
            ])
            ->and($processes->calls[4]->arguments)
            ->toBe([
                'sudo',
                'rm',
                '-f',
                '--',
                '/etc/wireguard/orbit-candidate.conf',
                '/etc/wireguard/.orbit.conf.rollback',
            ])
            ->and($ssh->commands)
            ->toHaveCount(1)
            ->and($peer->refresh()->wireguard_public_key)
            ->toBe(str_repeat(string: 'A', times: 43).'=');
    } finally {
        new Filesystem()->deleteDirectory($orbitHome);
    }
});

it('restores and restarts the previous server config when peer publication cannot activate it', function (): void {
    $processes = new class implements ProcessRunner {
        /** @var list<ProcessInvocation> */
        public array $calls = [];

        public function run(ProcessInvocation $invocation): CommandResult
        {
            $this->calls[] = $invocation;

            if (
                $invocation->arguments === ['sudo', 'systemctl', 'restart', 'wg-quick@orbit']
                || $invocation->arguments === ['sudo', 'bash', '-seu']
                && str_contains($invocation->input ?? '', 'systemctl restart wg-quick@orbit')
            ) {
                return new CommandResult(1, '', 'new server config failed', 2, false);
            }

            return new CommandResult(0, '', '', 2, false);
        }
    };
    $ssh = new class implements SshExecutor {
        /** @var list<RemoteCommand> */
        public array $commands = [];

        public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
        {
            $this->commands[] = $command;

            return new CommandResult(0, str_repeat(string: 'A', times: 43)."=\n", '', 2, false);
        }
    };
    [$converger, $peer, $connection, $orbitHome] = wireguard_peer_harness($processes, $ssh);

    try {
        expect(fn () => $converger->converge($peer, $connection))
            ->toThrow(function (NodeProvisioningException $exception): void {
                expect($exception->step)
                    ->toBe('wireguard-server-restart')
                    ->and($exception->errorCode)
                    ->toBe('vpn.server_start_failed')
                    ->and($exception->result?->stderr)
                    ->toBe('new server config failed');
            });
        $scripts = Collection::make($processes->calls)
            ->filter(static fn (ProcessInvocation $call): bool => $call->arguments === ['sudo', 'bash', '-seu'])
            ->pluck('input')
            ->filter(static fn (mixed $input): bool => is_string($input))
            ->implode("\n");

        expect($scripts)
            ->toContain(
                'cp --preserve=mode,ownership -- "$live" "$backup"',
                'mv -fT -- "$backup" "$live"',
                'systemctl restart wg-quick@orbit || true',
            )
            ->and($ssh->commands)
            ->toHaveCount(1);
    } finally {
        new Filesystem()->deleteDirectory($orbitHome);
    }
});

it('restores and restarts the previous peer config when remote activation fails', function (): void {
    $processes = new class implements ProcessRunner {
        public function run(ProcessInvocation $invocation): CommandResult
        {
            return new CommandResult(0, '', '', 2, false);
        }
    };
    $ssh = new class implements SshExecutor {
        /** @var list<RemoteCommand> */
        public array $commands = [];

        public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
        {
            $this->commands[] = $command;

            if (count($this->commands) === 1) {
                return new CommandResult(0, str_repeat(string: 'A', times: 43)."=\n", '', 2, false);
            }

            return new CommandResult(1, '', 'new peer config failed', 2, false);
        }
    };
    [$converger, $peer, $connection, $orbitHome] = wireguard_peer_harness($processes, $ssh);

    try {
        expect(fn () => $converger->converge($peer, $connection))
            ->toThrow(function (NodeProvisioningException $exception): void {
                expect($exception->step)
                    ->toBe('wireguard-peer-install')
                    ->and($exception->errorCode)
                    ->toBe('vpn.peer_config_failed')
                    ->and($exception->result?->stderr)
                    ->toBe('new peer config failed');
            });

        expect($ssh->commands[1]->input)
            ->toContain(
                'cp --preserve=mode,ownership -- "$live" "$backup"',
                'mv -fT -- "$backup" "$live"',
                'systemctl restart wg-quick@orbit || true',
            );
    } finally {
        new Filesystem()->deleteDirectory($orbitHome);
    }
});

it('uses a wg-quick compatible candidate filename', function (): void {
    $orbitHome = sys_get_temp_dir().'/orbit-vpn-'.Str::uuid();
    mkdir(directory: $orbitHome.'/wireguard', permissions: 0o700, recursive: true);
    file_put_contents(
        filename: $orbitHome.'/wireguard/private.key',
        data: str_repeat(string: 'S', times: 43).'=',
    );
    file_put_contents(
        filename: $orbitHome.'/wireguard/public.key',
        data: str_repeat(string: 'P', times: 43).'=',
    );

    try {
        $gateway = Node::query()->create([
            'name' => 'gateway',
            'public_ssh_host' => '85.9.218.89',
            'wireguard_address' => '10.44.0.1',
            'wireguard_public_key' => str_repeat(string: 'P', times: 43).'=',
        ]);
        $gateway->roles()->create(['role' => RoleName::Vpn]);
        $peer = Node::query()->create([
            'name' => 'app-dev',
            'public_ssh_host' => '94.237.40.75',
            'wireguard_address' => '10.44.0.2',
        ]);
        $settings = new VpnSettings(app(SettingRepository::class));
        $settings->configure(
            subnet: '10.44.0.0/24',
            endpoint: '10.0.0.2:51820',
            dnsServer: '10.0.0.2',
        );

        $processes = new class implements ProcessRunner {
            /** @var list<ProcessInvocation> */
            public array $calls = [];

            public function run(ProcessInvocation $invocation): CommandResult
            {
                $this->calls[] = $invocation;

                return new CommandResult(0, '', '', 2, false);
            }
        };
        $ssh = new class implements SshExecutor {
            public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
            {
                return new CommandResult(0, str_repeat(string: 'A', times: 43)."=\n", '', 2, false);
            }
        };
        $converger = new NativeWireGuardPeerConverger(
            configuration: new VpnConfigurationRepository($settings, $orbitHome),
            gatewayPeers: new NativeGatewayPeerProjectionManager(
                configuration: new VpnConfigurationRepository($settings, $orbitHome),
                serverRenderer: new WireGuardServerConfigRenderer,
                files: new ProtectedFileWriter,
                processes: $processes,
                orbitHome: $orbitHome,
            ),
            ssh: $ssh,
        );

        $converger->converge($peer, new SshConnection(
            host: '94.237.40.75',
            user: 'orbit',
            port: 22,
            identityFile: '/tmp/key',
            knownHostsFile: '/tmp/known_hosts',
        ));

        $candidatePath = Collection::make($processes->calls)
            ->flatMap(static fn (ProcessInvocation $invocation): array => $invocation->arguments)
            ->first(
                static fn (string $argument): bool => (
                    str_starts_with($argument, '/etc/wireguard/')
                    && $argument !== '/etc/wireguard/orbit.conf'
                ),
            );

        expect($candidatePath)
            ->toBe('/etc/wireguard/orbit-candidate.conf')
            ->and(basename($candidatePath, suffix: '.conf'))
            ->toBe('orbit-candidate')
            ->and(strlen(basename($candidatePath, suffix: '.conf')))
            ->toBeLessThanOrEqual(15)
            ->and(preg_match('/^[A-Za-z0-9_=+.-]{1,15}$/', basename($candidatePath, suffix: '.conf')))
            ->toBe(1);
    } finally {
        new Filesystem()->deleteDirectory($orbitHome);
    }
});

/** @return array{NativeWireGuardPeerConverger, Node, SshConnection, string} */
function wireguard_peer_harness(ProcessRunner $processes, SshExecutor $ssh): array
{
    $orbitHome = sys_get_temp_dir().'/orbit-vpn-'.Str::uuid();
    mkdir(directory: $orbitHome.'/wireguard', permissions: 0o700, recursive: true);
    file_put_contents(
        filename: $orbitHome.'/wireguard/private.key',
        data: str_repeat(string: 'S', times: 43).'=',
    );
    file_put_contents(
        filename: $orbitHome.'/wireguard/public.key',
        data: str_repeat(string: 'P', times: 43).'=',
    );
    $gateway = Node::query()->create([
        'name' => 'gateway',
        'public_ssh_host' => '85.9.218.89',
        'wireguard_address' => '10.44.0.1',
        'wireguard_public_key' => str_repeat(string: 'P', times: 43).'=',
    ]);
    $gateway->roles()->create(['role' => RoleName::Vpn]);
    $peer = Node::query()->create([
        'name' => 'app-dev',
        'public_ssh_host' => '94.237.40.75',
        'wireguard_address' => '10.44.0.2',
    ]);
    $settings = new VpnSettings(app(SettingRepository::class));
    $settings->configure(
        subnet: '10.44.0.0/24',
        endpoint: '10.0.0.2:51820',
        dnsServer: '10.0.0.2',
    );

    return [
        new NativeWireGuardPeerConverger(
            configuration: new VpnConfigurationRepository($settings, $orbitHome),
            gatewayPeers: new NativeGatewayPeerProjectionManager(
                configuration: new VpnConfigurationRepository($settings, $orbitHome),
                serverRenderer: new WireGuardServerConfigRenderer,
                files: new ProtectedFileWriter,
                processes: $processes,
                orbitHome: $orbitHome,
            ),
            ssh: $ssh,
        ),
        $peer,
        new SshConnection(
            host: '94.237.40.75',
            user: 'orbit',
            port: 22,
            identityFile: '/tmp/key',
            knownHostsFile: '/tmp/known_hosts',
        ),
        $orbitHome,
    ];
}
