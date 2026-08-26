<?php

declare(strict_types=1);

namespace App\Actions\Activities;

use App\Models\Activity;

final readonly class ShowActivityAction
{
    public function handle(Activity $activity): Activity
    {
        return $activity;
    }
}
