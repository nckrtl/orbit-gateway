<?php

declare(strict_types=1);

namespace App\Actions\Workspaces;

use App\Models\Workspace;
use Illuminate\Database\Eloquent\Collection;

final readonly class ListWorkspacesAction
{
    /** @return Collection<int, Workspace> */
    public function handle(): Collection
    {
        return Workspace::query()->with('instance')->latest('id')->get();
    }
}
