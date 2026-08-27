<?php

declare(strict_types=1);

namespace App\Domain\Tools;

final readonly class DebianVersionNormalizer
{
    public function __construct(
        private SemverVersionNormalizer $semver,
    ) {}

    public function normalize(string $raw): ?string
    {
        if (strlen($raw) > 255 || preg_match('/[\x00-\x1F\x7F]/', $raw) === 1) {
            return null;
        }

        $withoutEpoch = $raw;

        if (str_contains($raw, ':')) {
            [$epoch, $withoutEpoch] = explode(separator: ':', string: $raw, limit: 2);

            if (preg_match('/\A(?:0|[1-9]\d*)\z/D', $epoch) !== 1) {
                return null;
            }
        }

        $separator = strrpos(haystack: $withoutEpoch, needle: '-');
        $upstream = $separator === false
            ? $withoutEpoch
            : substr(string: $withoutEpoch, offset: 0, length: $separator);

        if (str_contains($upstream, '+')) {
            return null;
        }

        return $this->semver->normalize($upstream);
    }
}
