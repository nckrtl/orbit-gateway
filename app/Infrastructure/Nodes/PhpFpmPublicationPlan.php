<?php

declare(strict_types=1);

namespace App\Infrastructure\Nodes;

final readonly class PhpFpmPublicationPlan
{
    /**
     * @param  list<string>  $movingPoolNames
     * @param  list<array{version: string, retirement: bool}>  $publications
     */
    private function __construct(
        public array $movingPoolNames,
        public array $publications,
    ) {}

    /** @param array<string, string> $desiredPoolVersions */
    public static function from(
        PhpFpmInstalledProjection $installed,
        array $desiredPoolVersions,
        string $poolPattern,
    ): self {
        $movingPoolNames = [];
        $retirementVersions = [];
        $activationVersions = [];

        foreach ($installed->pools($poolPattern) as $installedPool) {
            $desiredVersion = $desiredPoolVersions[$installedPool['pool']] ?? null;

            if ($desiredVersion === $installedPool['version']) {
                continue;
            }

            $movingPoolNames[$installedPool['pool']] = true;
            $retirementVersions[$installedPool['version']] = true;

            if ($desiredVersion === null) {
                continue;
            }

            $activationVersions[$desiredVersion] = true;
        }

        $desiredVersions = self::sortedVersions(array_values($desiredPoolVersions));

        foreach ($installed->versions as $installedVersion) {
            if (in_array(needle: $installedVersion, haystack: $desiredVersions, strict: true)) {
                continue;
            }

            $retirementVersions[$installedVersion] = true;
        }

        $retirementVersions = self::sortedVersions(array_keys($retirementVersions));
        $activationVersions = self::sortedVersions(array_keys($activationVersions));
        $allVersions = self::sortedVersions([...$installed->versions, ...$desiredVersions]);
        $remainingVersions = array_values(array_filter(
            $allVersions,
            static fn (string $version): bool => (
                ! in_array(needle: $version, haystack: $retirementVersions, strict: true)
                && ! in_array(needle: $version, haystack: $activationVersions, strict: true)
            ),
        ));
        $publications = [];

        foreach ($retirementVersions as $version) {
            $publications[] = ['version' => $version, 'retirement' => true];
        }

        foreach ([...$activationVersions, ...$remainingVersions] as $version) {
            $publications[] = ['version' => $version, 'retirement' => false];
        }

        return new self(
            movingPoolNames: array_values(array_keys($movingPoolNames)),
            publications: $publications,
        );
    }

    /**
     * @param  array<int, string>  $versions
     * @return list<string>
     */
    private static function sortedVersions(array $versions): array
    {
        sort($versions, flags: SORT_NATURAL);

        return array_values(array_unique($versions));
    }
}
