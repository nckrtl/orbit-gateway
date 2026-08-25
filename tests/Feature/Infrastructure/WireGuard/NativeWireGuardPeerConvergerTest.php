<?php

declare(strict_types=1);

use App\Domain\Nodes\RoleName;
use App\Domain\Settings\SettingRepository;
use App\Domain\Settings\SettingScope;
use App\Domain\Settings\SettingScopeType;
use App\Infrastructure\Files\ProtectedFileWriter;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Processes\ProcessRunner;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshConnection;
use App\Infrastructure\Ssh\SshExecutor;
use App\Infrastructure\WireGuard\NativeWireGuardPeerConverger;
use App\Infrastructure\WireGuard\VpnConfigurationRepository;
use App\Infrastructure\WireGuard\WireGuardServerConfigRenderer;
use App\Models\Node;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Str;

it('installs the server peer set before starting the remote peer', function (): void {
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
        $settings = app(SettingRepository::class);
        $scope = new SettingScope(SettingScopeType::Gateway);
        $settings->put($scope, 'vpn.subnet', '10.44.0.0/24');
        $settings->put($scope, 'vpn.endpoint', '10.0.0.2:51820');
        $settings->put($scope, 'vpn.dns_server', '10.0.0.2');

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
            serverRenderer: new WireGuardServerConfigRenderer,
            files: new ProtectedFileWriter,
            processes: $processes,
            ssh: $ssh,
            orbitHome: $orbitHome,
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
            ->toHaveCount(4)
            ->and($processes->calls[0]->arguments)
            ->toContain('wg-quick', 'strip')
            ->and($ssh->commands)
            ->toHaveCount(2)
            ->and(file_get_contents($orbitHome.'/generated/wireguard/orbit.conf'))
            ->toContain('AllowedIPs = 10.44.0.2/32');
    } finally {
        new Filesystem()->deleteDirectory($orbitHome);
    }
});
