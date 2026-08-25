<?php

declare(strict_types=1);

namespace App\Domain\WireGuard;

use App\Domain\Settings\SettingRepository;
use App\Domain\Settings\SettingScope;
use App\Domain\Settings\SettingScopeType;
use App\Models\Node;
use RuntimeException;

final readonly class WireGuardAddressAllocator
{
    public function __construct(
        private SettingRepository $settings,
    ) {}

    public function next(): string
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
        $network = ip2long($networkAddress);
        $prefixLength = filter_var($prefix, FILTER_VALIDATE_INT);

        if ($network === false || ! is_int($prefixLength) || $prefixLength < 8 || $prefixLength > 30) {
            throw new RuntimeException("WireGuard subnet [{$subnet}] is invalid.");
        }

        $mask = (-1 << (32 - $prefixLength)) & 0xFFFF_FFFF;
        $first = ($network & $mask) + 1;
        $last = (($network & $mask) | (~$mask & 0xFFFF_FFFF)) - 1;
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

        throw new RuntimeException("WireGuard subnet [{$subnet}] has no free peer addresses.");
    }
}
