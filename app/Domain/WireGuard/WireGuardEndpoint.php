<?php

declare(strict_types=1);

namespace App\Domain\WireGuard;

final class WireGuardEndpoint
{
    public static function isValid(string $endpoint): bool
    {
        /** @var array<int, string> $matches */
        $matches = [];

        if ($endpoint === '' || preg_match('/[\x00-\x20\x7f]/', $endpoint) === 1) {
            return false;
        }

        if (preg_match('/\A\[([^]]+)]:(\d{1,5})\z/D', $endpoint, $matches) === 1) {
            return (
                filter_var($matches[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false
                && self::isValidPort($matches[2])
            );
        }

        if (substr_count(haystack: $endpoint, needle: ':') !== 1) {
            return false;
        }

        [$host, $port] = explode(separator: ':', string: $endpoint, limit: 2);

        return self::isValidHost($host) && self::isValidPort($port);
    }

    private static function isValidHost(string $host): bool
    {
        return (
            filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false
            || filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false
        );
    }

    private static function isValidPort(string $port): bool
    {
        if (! ctype_digit($port)) {
            return false;
        }

        $number = filter_var($port, FILTER_VALIDATE_INT);

        return is_int($number) && $number >= 1 && $number <= 65_535;
    }
}
