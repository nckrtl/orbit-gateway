<?php

declare(strict_types=1);

namespace App\Domain\AppDev;

use App\Models\Node;

interface PrivateDnsManager
{
    public function converge(?Node $pendingNode = null): void;
}
