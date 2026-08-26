<?php

declare(strict_types=1);

use App\Domain\Nodes\NodeProvisioningException;
use App\Domain\Nodes\RoleName;
use App\Domain\Settings\SettingRepository;
use App\Domain\WireGuard\VpnSettings;
use App\Infrastructure\WireGuard\VpnConfigurationRepository;
use App\Infrastructure\WireGuard\WireGuardServerConfigRenderer;
use App\Models\Node;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Str;

it('resolves peer overrides and renders the complete server peer set', function (): void {
    $orbitHome = sys_get_temp_dir().'/orbit-vpn-'.Str::uuid();
    mkdir(directory: $orbitHome.'/wireguard', permissions: 0o700, recursive: true);
    file_put_contents(filename: $orbitHome.'/wireguard/private.key', data: 'SERVER_PRIVATE');
    file_put_contents(filename: $orbitHome.'/wireguard/public.key', data: 'SERVER_PUBLIC');

    try {
        $gateway = Node::query()->create([
            'name' => 'gateway',
            'public_ssh_host' => '85.9.218.89',
            'wireguard_address' => '10.44.0.1',
            'wireguard_public_key' => 'SERVER_PUBLIC',
        ]);
        $gateway->roles()->create(['role' => RoleName::Vpn]);
        $peer = Node::query()->create([
            'name' => 'app-dev',
            'public_ssh_host' => '94.237.40.75',
            'wireguard_address' => '10.44.0.2',
            'wireguard_public_key' => 'PEER_PUBLIC',
            'wireguard_endpoint_override' => '10.0.0.2:51820',
            'dns_server_override' => '10.0.0.2',
        ]);
        $settings = new VpnSettings(app(SettingRepository::class));
        $settings->configure(subnet: '10.44.0.0/24', domain: 'test');
        $configuration = new VpnConfigurationRepository($settings, $orbitHome);

        $vpn = $configuration->forPeer($peer);
        $rendered = new WireGuardServerConfigRenderer()->render($vpn, Node::query()->get());

        expect($vpn->endpoint)
            ->toBe('10.0.0.2:51820')
            ->and($vpn->dnsServer)
            ->toBe('10.0.0.2')
            ->and($vpn->dnsThroughWireGuard)
            ->toBeFalse()
            ->and($vpn->peerAddress)
            ->toBe('10.44.0.2/24')
            ->and($rendered)
            ->toContain(
                'Address = 10.44.0.1/24',
                'PrivateKey = SERVER_PRIVATE',
                'PublicKey = PEER_PUBLIC',
                'AllowedIPs = 10.44.0.2/32',
            )
            ->not->toContain('PublicKey = SERVER_PUBLIC');
    } finally {
        new Filesystem()->deleteDirectory($orbitHome);
    }
});

it('rejects unsafe endpoint, DNS, and domain values before rendering peer shell hooks', function (): void {
    $orbitHome = sys_get_temp_dir().'/orbit-vpn-'.Str::uuid();
    mkdir(directory: $orbitHome.'/wireguard', permissions: 0o700, recursive: true);
    file_put_contents(filename: $orbitHome.'/wireguard/private.key', data: 'SERVER_PRIVATE');
    file_put_contents(filename: $orbitHome.'/wireguard/public.key', data: 'SERVER_PUBLIC');

    try {
        $gateway = Node::query()->create([
            'name' => 'gateway',
            'public_ssh_host' => '85.9.218.89',
            'wireguard_address' => '10.44.0.1',
            'wireguard_public_key' => 'SERVER_PUBLIC',
        ]);
        $gateway->roles()->create(['role' => RoleName::Vpn]);
        $peer = Node::query()->create([
            'name' => 'app-dev',
            'public_ssh_host' => '94.237.40.75',
            'wireguard_address' => '10.44.0.2',
            'dns_server_override' => '10.0.0.2; touch /tmp/orbit-injected',
        ]);
        $settings = new VpnSettings(app(SettingRepository::class));
        $settings->configure(subnet: '10.44.0.0/24');
        $configuration = new VpnConfigurationRepository($settings, $orbitHome);

        $peer->update([
            'wireguard_endpoint_override' => "10.0.0.2:51820\nPostUp = touch /tmp/orbit-injected",
        ]);

        expect(fn () => $configuration->forPeer($peer))
            ->toThrow(NodeProvisioningException::class, 'The WireGuard endpoint is invalid.');

        $peer->update(['wireguard_endpoint_override' => null]);

        expect(fn () => $configuration->forPeer($peer))
            ->toThrow(NodeProvisioningException::class, 'The DNS server is invalid.');

        $peer->update(['dns_server_override' => null]);

        expect($configuration->forPeer($peer)->dnsThroughWireGuard)
            ->toBeTrue();

        $peer->update(['dns_server_override' => '10.0.0.2']);
        $settings->configure(subnet: '10.44.0.0/24', domain: 'orbit; touch /tmp/orbit-injected');

        expect(fn () => $configuration->forPeer($peer))
            ->toThrow(NodeProvisioningException::class, 'The private DNS domain is invalid.');
    } finally {
        new Filesystem()->deleteDirectory($orbitHome);
    }
});
