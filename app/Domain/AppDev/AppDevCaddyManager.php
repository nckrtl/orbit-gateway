<?php

declare(strict_types=1);

namespace App\Domain\AppDev;

use App\Models\Node;

interface AppDevCaddyManager
{
    public function converge(Node $node): void;

    public function remove(Node $node): void;
}
