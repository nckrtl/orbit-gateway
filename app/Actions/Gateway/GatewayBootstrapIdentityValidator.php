<?php

declare(strict_types=1);

namespace App\Actions\Gateway;

use App\Data\Gateway\BootstrapGatewayData;
use InvalidArgumentException;

/** @mago-expect lint:cyclomatic-complexity Static gateway identity validation centralizes independent boundary checks before host effects. */
final readonly class GatewayBootstrapIdentityValidator
{
    public function validate(BootstrapGatewayData $data): void
    {
        $hostname = "{$data->name}.{$data->domain}";

        if (filter_var($hostname, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
            throw new InvalidArgumentException("Gateway hostname [{$hostname}] is invalid.");
        }

        if (! $this->isHost($data->publicHost)) {
            throw new InvalidArgumentException("Gateway public host [{$data->publicHost}] is invalid.");
        }

        if (filter_var($data->wireguardAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            throw new InvalidArgumentException("Gateway WireGuard address [{$data->wireguardAddress}] is invalid.");
        }

        $this->validateSubnet($data->wireguardSubnet, $data->wireguardAddress);

        if (filter_var($data->dnsServer, FILTER_VALIDATE_IP) === false) {
            throw new InvalidArgumentException("Gateway DNS server [{$data->dnsServer}] is invalid.");
        }

        if ($data->wireguardPort < 1 || $data->wireguardPort > 65_535) {
            throw new InvalidArgumentException('Gateway WireGuard port is invalid.');
        }

        $matches = [];

        if (preg_match('/^(.+):([0-9]{1,5})$/', $data->wireguardEndpoint, $matches) !== 1) {
            throw new InvalidArgumentException("Gateway WireGuard endpoint [{$data->wireguardEndpoint}] is invalid.");
        }

        $endpointPort = filter_var($matches[2], FILTER_VALIDATE_INT);

        if (! $this->isHost($matches[1]) || ! is_int($endpointPort) || $endpointPort < 1 || $endpointPort > 65_535) {
            throw new InvalidArgumentException("Gateway WireGuard endpoint [{$data->wireguardEndpoint}] is invalid.");
        }

        if (
            $data->privateInterface !== null
            && preg_match('/^[A-Za-z0-9_.:+-]{1,15}$/', $data->privateInterface) !== 1
        ) {
            throw new InvalidArgumentException("Gateway private interface [{$data->privateInterface}] is invalid.");
        }
    }

    private function isHost(string $host): bool
    {
        return (
            filter_var($host, FILTER_VALIDATE_IP) !== false
            || filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false
        );
    }

    private function validateSubnet(string $subnet, string $address): void
    {
        [$network, $prefix] = array_pad(
            explode(separator: '/', string: $subnet, limit: 2),
            length: 2,
            value: null,
        );
        $networkValue = is_string($network) ? ip2long($network) : false;
        $addressValue = ip2long($address);
        $prefixLength = filter_var($prefix, FILTER_VALIDATE_INT);

        if (
            $networkValue === false
            || $addressValue === false
            || ! is_int($prefixLength)
            || $prefixLength < 8
            || $prefixLength > 30
        ) {
            throw new InvalidArgumentException("Gateway WireGuard subnet [{$subnet}] is invalid.");
        }

        $mask = -1 << (32 - $prefixLength);

        if (($networkValue & $mask) !== ($addressValue & $mask)) {
            throw new InvalidArgumentException("Gateway WireGuard address [{$address}] is outside [{$subnet}].");
        }
    }
}
