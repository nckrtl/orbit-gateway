<?php

declare(strict_types=1);

namespace App\Actions\Apps;

use App\Models\App as OrbitApp;
use Illuminate\Database\Eloquent\Collection;

final readonly class ListAppsAction
{
    /** @return Collection<int, OrbitApp> */
    public function handle(): Collection
    {
        return OrbitApp::query()->latest('id')->get();
    }
}
