<?php

declare(strict_types=1);

namespace App\Domain\AppProd;

use App\Models\Instance;

interface AppProdUserManager
{
    public function converge(Instance $instance): void;

    public function remove(Instance $instance): void;
}
