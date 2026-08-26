<?php

declare(strict_types=1);

namespace App\Domain\Nodes;

final class NodeTld
{
    private const string PATTERN = '/\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\z/D';

    public static function normalize(string $tld): string
    {
        $normalized = trim($tld);

        if (str_starts_with($normalized, '.')) {
            $normalized = substr(string: $normalized, offset: 1);
        }

        return strtolower($normalized);
    }

    public static function isValid(string $tld): bool
    {
        $normalized = self::normalize($tld);

        return $normalized !== '' && strlen($normalized) <= 253 && preg_match(self::PATTERN, $normalized) === 1;
    }
}
