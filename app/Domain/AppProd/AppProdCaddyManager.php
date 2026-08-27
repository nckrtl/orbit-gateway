<?php

declare(strict_types=1);

namespace App\Domain\AppProd;

use App\Models\Node;

interface AppProdCaddyManager
{
    public function converge(Node $node): void;

    public function remove(Node $node): void;
}
