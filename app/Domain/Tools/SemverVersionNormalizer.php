<?php

declare(strict_types=1);

namespace App\Domain\Tools;

final readonly class SemverVersionNormalizer
{
    private const string VERSION_PATTERN = <<<'REGEX'
        /\Av?(0|[1-9]\d*)\.(0|[1-9]\d*)(?:\.(0|[1-9]\d*))?(-(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*)?(\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\z/D
        REGEX;

    public function normalize(string $raw): ?string
    {
        $matches = [];

        if (
            strlen($raw) > 255
            || preg_match(self::VERSION_PATTERN, $raw, $matches, flags: PREG_UNMATCHED_AS_NULL) !== 1
        ) {
            return null;
        }

        $patch = $matches[3] ?? '0';
        $prerelease = $matches[4] ?? '';
        $build = $matches[5] ?? '';

        return "{$matches[1]}.{$matches[2]}.{$patch}{$prerelease}{$build}";
    }
}
