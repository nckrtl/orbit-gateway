<?php

declare(strict_types=1);

namespace App\Actions\Instances;

use App\Models\Instance;
use Illuminate\Database\Eloquent\Collection;

final readonly class ListInstancesAction
{
    /** @return Collection<int, Instance> */
    public function handle(): Collection
    {
        return Instance::query()->latest('id')->get();
    }
}
