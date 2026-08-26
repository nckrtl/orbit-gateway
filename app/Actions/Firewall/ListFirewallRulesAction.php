<?php

declare(strict_types=1);

namespace App\Actions\Firewall;

use App\Models\FirewallRule;
use App\Models\Node;
use Illuminate\Support\Collection;

final readonly class ListFirewallRulesAction
{
    /** @return Collection<int, FirewallRule> */
    public function execute(Node $node): Collection
    {
        return $node->firewallRules()->with('node')->orderBy('name')->get();
    }
}
