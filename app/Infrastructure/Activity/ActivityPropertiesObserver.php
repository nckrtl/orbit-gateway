<?php

declare(strict_types=1);

namespace App\Infrastructure\Activity;

use App\Models\Activity;

final readonly class ActivityPropertiesObserver
{
    public function __construct(
        private CommandActivityInputSanitizer $sanitizer,
    ) {}

    public function saving(Activity $activity): void
    {
        $properties = $activity->properties?->toArray() ?? [];

        $activity->setAttribute('properties', $this->sanitizer->sanitizeProperties($properties));
    }
}
