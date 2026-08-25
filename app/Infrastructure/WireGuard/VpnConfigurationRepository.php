<?php

declare(strict_types=1);

namespace App\Infrastructure\WireGuard;

use App\Domain\Nodes\NodeProvisioningException;
use App\Domain\Nodes\RoleName;
use App\Domain\Settings\SettingRepository;
use App\Domain\Settings\SettingScope;
use App\Domain\Settings\SettingScopeType;
use App\Models\Node;

/** @mago-expect lint:cyclomatic-complexity */
final readonly class VpnConfigurationRepository
{
    public function __construct(
        private SettingRepository $settings,
        private string $orbitHome,
    ) {}

    public function forPeer(Node $peer): VpnConfiguration
    {
        $server = Node::query()
            ->whereHas('roles', static fn ($query) => $query->where('role', RoleName::Vpn->value))
            ->first();

        if (! $server instanceof Node || ! is_string($server->wireguard_address)) {
            throw $this->invalid('The VPN role has no configured server node.');
        }

        if (! is_string($peer->wireguard_address)) {
            throw $this->invalid("Node [{$peer->name}] has no WireGuard address.");
        }

        $scope = new SettingScope(SettingScopeType::Gateway);
        $subnet = $this->settings->get($scope, 'vpn.subnet') ?? '10.44.0.0/24';
        $prefixLength = $this->prefixLength($subnet);
        $port = filter_var($this->settings->get($scope, 'vpn.port') ?? '51820', FILTER_VALIDATE_INT);

        if (! is_int($port) || $port < 1 || $port > 65_535) {
            throw $this->invalid('The WireGuard port is invalid.');
        }

        $serverPrivateKey = $this->key('private');
        $serverPublicKey = $this->key('public');
        $serverAddress = $server->wireguard_address;
        $peerAddress = $peer->wireguard_address;
        $endpoint =
            $peer->wireguard_endpoint_override ?? $this->settings->get($scope, 'vpn.endpoint')
                ?? "{$server->public_ssh_host}:{$port}";
        $dnsServer = $peer->dns_server_override ?? $this->settings->get($scope, 'vpn.dns_server') ?? $serverAddress;

        if ($endpoint === '' || ! is_string($dnsServer) || $dnsServer === '') {
            throw $this->invalid('The WireGuard endpoint or DNS server is invalid.');
        }

        return new VpnConfiguration(
            server: $server,
            subnet: $subnet,
            prefixLength: $prefixLength,
            port: $port,
            endpoint: $endpoint,
            dnsServer: $dnsServer,
            domain: $this->settings->get($scope, 'vpn.domain') ?? 'orbit',
            serverAddress: "{$serverAddress}/{$prefixLength}",
            peerAddress: "{$peerAddress}/{$prefixLength}",
            serverPrivateKey: $serverPrivateKey,
            serverPublicKey: $serverPublicKey,
        );
    }

    private function prefixLength(string $subnet): int
    {
        $parts = explode(separator: '/', string: $subnet, limit: 2);
        $prefix = filter_var($parts[1] ?? null, FILTER_VALIDATE_INT);

        if (! is_int($prefix) || $prefix < 8 || $prefix > 30 || ip2long($parts[0]) === false) {
            throw $this->invalid("WireGuard subnet [{$subnet}] is invalid.");
        }

        return $prefix;
    }

    private function key(string $name): string
    {
        $path = rtrim(string: $this->orbitHome, characters: '/')."/wireguard/{$name}.key";
        $key = file_get_contents($path);

        if (! is_string($key) || trim($key) === '') {
            throw $this->invalid("WireGuard key [{$path}] is missing.");
        }

        return trim($key);
    }

    private function invalid(string $message): NodeProvisioningException
    {
        return new NodeProvisioningException(
            step: 'wireguard-configuration',
            errorCode: 'vpn.configuration_invalid',
            message: $message,
        );
    }
}
