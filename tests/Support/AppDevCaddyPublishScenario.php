<?php

declare(strict_types=1);

namespace Tests\Support;

/** @mago-expect lint:excessive-parameter-list Explicit flags define complete Caddy publication failure scenarios. */
final readonly class AppDevCaddyPublishScenario
{
    /** @param array<string, string> $existingOrbitFragments */
    private function __construct(
        public string $liveMain,
        public ?string $packageDefault,
        public array $existingOrbitFragments,
        public bool $liveIsOrbitAggregate,
        public bool $failValidation,
        public bool $failActivation,
    ) {}

    public static function packageDefault(string $liveMain, string $packageDefault): self
    {
        return new self(
            liveMain: $liveMain,
            packageDefault: $packageDefault,
            existingOrbitFragments: [],
            liveIsOrbitAggregate: false,
            failValidation: false,
            failActivation: false,
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
            failActivation: false,
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
            failActivation: false,
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
            failActivation: false,
        );
    }

    /** @param array<string, string> $existingOrbitFragments */
    public static function orbitAggregateWithActivationFailure(
        string $liveMain,
        array $existingOrbitFragments,
    ): self {
        return new self(
            liveMain: $liveMain,
            packageDefault: null,
            existingOrbitFragments: $existingOrbitFragments,
            liveIsOrbitAggregate: true,
            failValidation: false,
            failActivation: true,
        );
    }

    public static function modifiedConfigWithActivationFailure(string $liveMain, string $packageDefault): self
    {
        return new self(
            liveMain: $liveMain,
            packageDefault: $packageDefault,
            existingOrbitFragments: [],
            liveIsOrbitAggregate: false,
            failValidation: false,
            failActivation: true,
        );
    }
}
