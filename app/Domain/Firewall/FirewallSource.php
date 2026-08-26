<?php

declare(strict_types=1);

namespace App\Domain\Firewall;

use InvalidArgumentException;

final class FirewallSource
{
    public static function normalize(string $source): string
    {
        if ($source !== trim($source) || $source === '') {
            throw new InvalidArgumentException('The firewall source is invalid.');
        }

        if ($source === 'any') {
            return $source;
        }

        $parts = explode('/', $source, limit: 2);
        $address = $parts[0];
        $prefix = $parts[1] ?? null;

        if ($address === '') {
            throw new InvalidArgumentException('The firewall source is invalid.');
        }

        $packed = inet_pton($address);

        if ($packed === false) {
            throw new InvalidArgumentException('The firewall source is invalid.');
        }

        $maximumPrefix = strlen($packed) * 8;

        if ($prefix === null) {
            return self::canonicalAddress($packed);
        }

        if (preg_match('/\A(?:0|[1-9]\d{0,2})\z/D', $prefix) !== 1) {
            throw new InvalidArgumentException('The firewall CIDR prefix is invalid.');
        }

        $prefixLength = (int) $prefix;

        if ($prefixLength > $maximumPrefix) {
            throw new InvalidArgumentException('The firewall CIDR prefix is invalid.');
        }

        $network = self::networkAddress($packed, $prefixLength);
        $normalized = self::canonicalAddress($network);

        return $prefixLength === $maximumPrefix ? $normalized : "{$normalized}/{$prefixLength}";
    }

    public static function family(string $source): string
    {
        if ($source === 'any') {
            return 'both';
        }

        $address = explode('/', $source, limit: 2)[0];

        return filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false ? 'v4' : 'v6';
    }

    private static function networkAddress(string $packed, int $prefixLength): string
    {
        $network = '';

        for ($index = 0; $index < strlen($packed); $index++) {
            $bits = min(8, max(0, $prefixLength - ($index * 8)));
            $mask = $bits === 0 ? 0 : (0xff << (8 - $bits)) & 0xff;
            $network .= chr(ord($packed[$index]) & $mask);
        }

        return $network;
    }

    private static function canonicalAddress(string $packed): string
    {
        $address = inet_ntop($packed);

        if ($address === false) {
            throw new InvalidArgumentException('The firewall source is invalid.');
        }

        return $address;
    }
}
