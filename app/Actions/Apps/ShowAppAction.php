<?php

declare(strict_types=1);

namespace App\Actions\Apps;

use App\Models\App as OrbitApp;

final readonly class ShowAppAction
{
    public function handle(OrbitApp $app): OrbitApp
    {
        return $app;
    }
}
