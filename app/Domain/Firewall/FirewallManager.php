<?php

declare(strict_types=1);

namespace App\Domain\Firewall;

use App\Models\FirewallRule;

interface FirewallManager
{
    public function converge(FirewallRule $rule): FirewallBackendStatus;

    public function remove(FirewallRule $rule): FirewallBackendStatus;
}
