<?php

declare(strict_types=1);

namespace App\Domain\WireGuard;

use App\Domain\Settings\SettingRepository;
use App\Domain\Settings\SettingScope;
use App\Domain\Settings\SettingScopeType;
use App\Domain\Shared\ResourceOperationException;
use App\Models\Node;

/** @mago-expect lint:cyclomatic-complexity Peer allocation centralizes format, subnet, and uniqueness checks. */
final readonly class WireGuardAddressAllocator
{
    public function __construct(
        private SettingRepository $settings,
    ) {}

    public function next(): string
    {
        [$first, $last, $subnet] = $this->usableRange();
        $used = Node::query()
            ->whereNotNull('wireguard_address')
            ->pluck('wireguard_address')
            ->filter(static fn (mixed $address): bool => is_string($address))
            ->all();

        for ($candidate = $first; $candidate <= $last; $candidate++) {
            $address = long2ip($candidate);

            if (! in_array($address, $used, strict: true)) {
                return $address;
            }
        }

        throw new ResourceOperationException(
            errorCode: 'vpn.peer_address_exhausted',
            message: "WireGuard subnet [{$subnet}] has no free peer addresses.",
            status: 409,
        );
    }

    public function forProvisioning(?string $requestedAddress, ?Node $node = null): string
    {
        if ($requestedAddress === null) {
            return $this->next();
        }

        [$first, $last] = $this->usableRange();
        $address = filter_var($requestedAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
        $numericAddress = is_string($address) ? ip2long($address) : false;

        if ($numericAddress === false || $numericAddress < $first || $numericAddress > $last) {
            throw new ResourceOperationException(
                errorCode: 'vpn.peer_address_invalid',
                message: "WireGuard peer address [{$requestedAddress}] is outside the usable subnet range.",
            );
        }

        $query = Node::query()->where('wireguard_address', $requestedAddress);

        if ($node instanceof Node && $node->exists) {
            $query->whereKeyNot($node->getKey());
        }

        if ($query->exists()) {
            throw new ResourceOperationException(
                errorCode: 'vpn.peer_address_taken',
                message: "WireGuard peer address [{$requestedAddress}] is already assigned.",
                status: 409,
            );
        }

        return $requestedAddress;
    }

    /** @return array{int, int, string} */
    private function usableRange(): array
    {
        $subnet =
            $this->settings->get(
                new SettingScope(SettingScopeType::Gateway),
                'vpn.subnet',
            ) ?? '10.44.0.0/24';
        [$networkAddress, $prefix] = array_pad(
            array: explode(separator: '/', string: $subnet, limit: 2),
            length: 2,
            value: '',
        );
        $network = filter_var($networkAddress, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
        $numericNetwork = is_string($network) ? ip2long($network) : false;
        $prefixLength = filter_var($prefix, FILTER_VALIDATE_INT);

        if ($numericNetwork === false || ! is_int($prefixLength) || $prefixLength < 8 || $prefixLength > 30) {
            throw $this->invalidSubnet($subnet);
        }

        $mask = (-1 << (32 - $prefixLength)) & 0xFFFF_FFFF;
        $networkStart = $numericNetwork & $mask;

        if ($networkStart !== $numericNetwork) {
            throw $this->invalidSubnet($subnet);
        }

        return [
            $networkStart + 1,
            ($networkStart | (~$mask & 0xFFFF_FFFF)) - 1,
            $subnet,
        ];
    }

    private function invalidSubnet(string $subnet): ResourceOperationException
    {
        return new ResourceOperationException(
            errorCode: 'vpn.subnet_invalid',
            message: "WireGuard subnet [{$subnet}] is invalid.",
        );
    }
}
