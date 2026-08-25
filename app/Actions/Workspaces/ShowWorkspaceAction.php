<?php

declare(strict_types=1);

namespace App\Actions\Workspaces;

use App\Models\Workspace;

final readonly class ShowWorkspaceAction
{
    public function handle(Workspace $workspace): Workspace
    {
        return $workspace->load('instance');
    }
}
