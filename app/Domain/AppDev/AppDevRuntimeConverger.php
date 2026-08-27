<?php

declare(strict_types=1);

namespace App\Domain\AppDev;

use App\Models\Instance;
use App\Models\Workspace;

interface AppDevRuntimeConverger
{
    public function convergeInstance(Instance $instance): void;

    public function removeInstance(Instance $instance): void;

    public function unpublishInstance(Instance $instance): void;

    public function convergeWorkspace(Workspace $workspace): void;

    public function removeWorkspace(Workspace $workspace): void;

    public function unpublishWorkspace(Workspace $workspace): void;
}
