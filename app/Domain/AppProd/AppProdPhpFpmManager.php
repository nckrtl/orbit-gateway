<?php

declare(strict_types=1);

namespace App\Domain\AppProd;

use App\Models\Node;

interface AppProdPhpFpmManager
{
    public function converge(Node $node): void;
}
