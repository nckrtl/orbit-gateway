<?php

declare(strict_types=1);

namespace Tests\Support;

final readonly class AppDevCaddyPublishScenario
{
    /** @param array<string, string> $existingOrbitFragments */
    private function __construct(
        public string $liveMain,
        public ?string $packageDefault,
        public array $existingOrbitFragments,
        public bool $liveIsOrbitAggregate,
        public bool $failValidation,
    ) {}

    public static function packageDefault(string $liveMain, string $packageDefault): self
    {
        return new self(
            liveMain: $liveMain,
            packageDefault: $packageDefault,
            existingOrbitFragments: [],
            liveIsOrbitAggregate: false,
            failValidation: false,
        );
    }

    /** @param array<string, string> $existingOrbitFragments */
    public static function orbitAggregate(string $liveMain, array $existingOrbitFragments): self
    {
        return new self(
            liveMain: $liveMain,
            packageDefault: null,
            existingOrbitFragments: $existingOrbitFragments,
            liveIsOrbitAggregate: true,
            failValidation: false,
        );
    }

    public static function modifiedConfig(string $liveMain, string $packageDefault): self
    {
        return new self(
            liveMain: $liveMain,
            packageDefault: $packageDefault,
            existingOrbitFragments: [],
            liveIsOrbitAggregate: false,
            failValidation: false,
        );
    }

    public static function modifiedConfigWithValidationFailure(string $liveMain, string $packageDefault): self
    {
        return new self(
            liveMain: $liveMain,
            packageDefault: $packageDefault,
            existingOrbitFragments: [],
            liveIsOrbitAggregate: false,
            failValidation: true,
        );
    }
}
