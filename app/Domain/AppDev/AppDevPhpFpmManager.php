<?php

declare(strict_types=1);

namespace App\Domain\AppDev;

use App\Models\Node;

interface AppDevPhpFpmManager
{
    public function converge(Node $node): void;
}
