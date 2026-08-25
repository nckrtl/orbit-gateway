<?php

declare(strict_types=1);

namespace App\Models;

use Illuminate\Support\Collection;
use Spatie\Activitylog\Models\Activity as SpatieActivity;

/**
 * @property string $request_id
 * @property string $command
 * @property string|null $caller_ip
 * @property string $status
 * @property int|null $duration_ms
 * @property int|null $exit_code
 * @property string|null $error_code
 * @property Collection<array-key, mixed>|null $properties
 */
final class Activity extends SpatieActivity
{
    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'attribute_changes' => 'collection',
            'properties' => 'collection',
            'duration_ms' => 'integer',
            'exit_code' => 'integer',
        ];
    }
}
