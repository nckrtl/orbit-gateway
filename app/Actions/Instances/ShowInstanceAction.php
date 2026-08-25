<?php

declare(strict_types=1);

namespace App\Actions\Instances;

use App\Models\Instance;

final readonly class ShowInstanceAction
{
    public function handle(Instance $instance): Instance
    {
        return $instance;
    }
}
