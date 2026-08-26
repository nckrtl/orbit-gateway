<?php

declare(strict_types=1);

namespace App\Infrastructure\WireGuard;

use Illuminate\Http\Request;

final class WireGuardPeerAddressResolver
{
    public function resolve(Request $request): ?string
    {
        $remoteAddress = $request->server('REMOTE_ADDR');

        if (! is_string($remoteAddress) || ! $this->isIpAddress($remoteAddress)) {
            return null;
        }

        if (! $this->isLoopback($remoteAddress)) {
            return $remoteAddress;
        }

        if ($request->server('ORBIT_TRUSTED_LOCAL_PROXY') !== '1') {
            return null;
        }

        $peerAddress = $request->server('ORBIT_PEER_ADDRESS');

        if (! is_string($peerAddress) || ! $this->isIpAddress($peerAddress) || $this->isLoopback($peerAddress)) {
            return null;
        }

        return $peerAddress;
    }

    private function isIpAddress(string $value): bool
    {
        return (
            trim($value) === $value
            && preg_match('/[\x00-\x20,]/', $value) !== 1
            && filter_var($value, FILTER_VALIDATE_IP) !== false
        );
    }

    private function isLoopback(string $address): bool
    {
        $binary = inet_pton($address);

        if ($binary === false) {
            return false;
        }

        return strlen($binary) === 4 && ord($binary[0]) === 127 || $binary === str_repeat(string: "\0", times: 15)."\1";
    }
}
