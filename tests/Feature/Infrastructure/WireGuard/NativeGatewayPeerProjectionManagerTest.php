<?php

declare(strict_types=1);

use App\Domain\Nodes\RoleName;
use App\Domain\Settings\SettingRepository;
use App\Domain\WireGuard\VpnSettings;
use App\Infrastructure\Files\ProtectedFileWriter;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Processes\ProcessRunner;
use App\Infrastructure\WireGuard\NativeGatewayPeerProjectionManager;
use App\Infrastructure\WireGuard\VpnConfigurationRepository;
use App\Infrastructure\WireGuard\WireGuardServerConfigRenderer;
use App\Models\Node;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Str;

it('removes and restores only the selected peer in the serialized gateway projection', function (): void {
    $orbitHome = sys_get_temp_dir().'/orbit-vpn-projection-'.Str::uuid();
    mkdir(directory: $orbitHome.'/wireguard', permissions: 0o700, recursive: true);
    file_put_contents($orbitHome.'/wireguard/private.key', str_repeat(string: 'S', times: 43).'=');
    file_put_contents($orbitHome.'/wireguard/public.key', str_repeat(string: 'P', times: 43).'=');

    try {
        $gateway = Node::query()->create([
            'name' => 'gateway',
            'public_ssh_host' => '85.9.218.89',
            'wireguard_address' => '10.44.0.1',
            'wireguard_public_key' => str_repeat(string: 'P', times: 43).'=',
        ]);
        $gateway->roles()->create(['role' => RoleName::Vpn]);
        $removedPeer = Node::query()->create([
            'name' => 'removed-peer',
            'public_ssh_host' => '94.237.40.75',
            'wireguard_address' => '10.44.0.2',
            'wireguard_public_key' => str_repeat(string: 'A', times: 43).'=',
        ]);
        Node::query()->create([
            'name' => 'remaining-peer',
            'public_ssh_host' => '94.237.40.76',
            'wireguard_address' => '10.44.0.3',
            'wireguard_public_key' => str_repeat(string: 'B', times: 43).'=',
        ]);
        $settings = new VpnSettings(app(SettingRepository::class));
        $settings->configure(
            subnet: '10.44.0.0/24',
            endpoint: '85.9.218.89:51820',
            dnsServer: '10.44.0.1',
        );

        $processes = new class($orbitHome) implements ProcessRunner {
            /** @var list<ProcessInvocation> */
            public array $calls = [];

            public bool $observedProjectionLock = false;

            public function __construct(
                private readonly string $orbitHome,
            ) {}

            public function run(ProcessInvocation $invocation): CommandResult
            {
                $this->calls[] = $invocation;

                if (count($this->calls) === 1) {
                    $lock = fopen($this->orbitHome.'/locks/wireguard-server.lock', mode: 'c+');

                    if ($lock === false) {
                        throw new RuntimeException('Could not inspect the WireGuard projection lock.');
                    }

                    $acquired = flock($lock, LOCK_EX | LOCK_NB);
                    $this->observedProjectionLock = ! $acquired;

                    if ($acquired) {
                        flock($lock, LOCK_UN);
                    }

                    fclose($lock);
                }

                return new CommandResult(0, '', '', 1, false);
            }
        };
        $manager = new NativeGatewayPeerProjectionManager(
            configuration: new VpnConfigurationRepository($settings, $orbitHome),
            serverRenderer: new WireGuardServerConfigRenderer,
            files: new ProtectedFileWriter,
            processes: $processes,
            orbitHome: $orbitHome,
        );

        $manager->remove($removedPeer);

        expect(file_get_contents($orbitHome.'/generated/wireguard/orbit.conf'))
            ->not
            ->toContain('# removed-peer', 'AllowedIPs = 10.44.0.2/32')
            ->toContain('# remaining-peer', 'AllowedIPs = 10.44.0.3/32')
            ->and($processes->calls)
            ->toHaveCount(5)
            ->and($processes->observedProjectionLock)
            ->toBeTrue();

        $manager->restore($removedPeer);

        expect(file_get_contents($orbitHome.'/generated/wireguard/orbit.conf'))
            ->toContain(
                '# removed-peer',
                'AllowedIPs = 10.44.0.2/32',
                '# remaining-peer',
                'AllowedIPs = 10.44.0.3/32',
            )
            ->and($processes->calls)
            ->toHaveCount(10);
    } finally {
        new Filesystem()->deleteDirectory($orbitHome);
    }
});
