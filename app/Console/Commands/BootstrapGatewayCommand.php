<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Actions\Gateway\BootstrapGatewayAction;
use App\Data\Gateway\BootstrapGatewayData;
use Illuminate\Console\Command;

final class BootstrapGatewayCommand extends Command
{
    #[\Override]
    protected $signature = 'orbit:bootstrap
        {public-host : Gateway public IP or hostname}
        {--name=gateway : Gateway node name}
        {--wireguard-address=10.44.0.1 : Gateway WireGuard address}
        {--wireguard-subnet=10.44.0.0/24 : Orbit WireGuard subnet}
        {--wireguard-port=51820 : Public WireGuard UDP port}
        {--wireguard-endpoint= : Public WireGuard endpoint}
        {--dns-server= : Default DNS server for peers}
        {--domain=orbit : Private DNS domain}
        {--private-interface= : Optional private underlay interface}';

    #[\Override]
    protected $description = 'Initialize gateway keys, authority, roles, and VPN settings.';

    public function handle(BootstrapGatewayAction $action): int
    {
        $publicHost = $this->stringArgument('public-host');
        $wireguardAddress = $this->stringOption('wireguard-address');
        $wireguardSubnet = $this->stringOption('wireguard-subnet');
        $wireguardPort = $this->option('wireguard-port');

        if (
            $publicHost === null
            || $wireguardAddress === null
            || $wireguardSubnet === null
            || ! is_numeric($wireguardPort)
        ) {
            $this->error('Gateway bootstrap arguments are invalid.');

            return self::FAILURE;
        }

        $port = (int) $wireguardPort;
        $endpoint = $this->stringOption('wireguard-endpoint') ?? "{$publicHost}:{$port}";
        $node = $action->execute(new BootstrapGatewayData(
            publicHost: $publicHost,
            wireguardAddress: $wireguardAddress,
            wireguardSubnet: $wireguardSubnet,
            wireguardEndpoint: $endpoint,
            dnsServer: $this->stringOption('dns-server') ?? $wireguardAddress,
            domain: $this->stringOption('domain') ?? 'orbit',
            privateInterface: $this->stringOption('private-interface'),
            wireguardPort: $port,
            name: $this->stringOption('name') ?? 'gateway',
        ));

        $this->info("Gateway [{$node->name}] initialized.");

        return self::SUCCESS;
    }

    private function stringArgument(string $name): ?string
    {
        $value = $this->argument($name);

        return is_string($value) && $value !== '' ? $value : null;
    }

    private function stringOption(string $name): ?string
    {
        $value = $this->option($name);

        return is_string($value) && $value !== '' ? $value : null;
    }
}
