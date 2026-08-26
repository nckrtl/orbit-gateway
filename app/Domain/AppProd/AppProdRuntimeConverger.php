<?php

declare(strict_types=1);

namespace App\Domain\AppProd;

use App\Models\Instance;

interface AppProdRuntimeConverger
{
    public function convergeInstance(Instance $instance): void;

    public function removeInstance(Instance $instance): void;
}
