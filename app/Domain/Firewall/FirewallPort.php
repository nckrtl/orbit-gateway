<?php

declare(strict_types=1);

namespace App\Domain\Firewall;

use InvalidArgumentException;

final class FirewallPort
{
    public static function normalize(string $port): string
    {
        if (preg_match('/\A\d{1,5}(?::\d{1,5})?\z/D', $port) !== 1) {
            throw new InvalidArgumentException('The firewall port is invalid.');
        }

        $ports = array_map(intval(...), explode(':', $port));
        $start = $ports[0];
        $end = $ports[1] ?? null;

        if ($start < 1 || $start > 65_535 || $end !== null && ($end < $start || $end > 65_535)) {
            throw new InvalidArgumentException('The firewall port is invalid.');
        }

        return $end === null ? (string) $start : "{$start}:{$end}";
    }

    public static function contains(string $port, int $candidate): bool
    {
        $ports = array_map(intval(...), explode(':', $port));

        return $candidate >= $ports[0] && $candidate <= ($ports[1] ?? $ports[0]);
    }
}
