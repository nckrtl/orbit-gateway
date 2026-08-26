<?php

declare(strict_types=1);

namespace App\Data\Firewall;

use App\Domain\Firewall\FirewallAction;

final readonly class StoreFirewallRuleData
{
    public function __construct(
        public string $name,
        public FirewallAction $action,
        public string $source,
        public string $protocol,
        public string $port,
    ) {}
}
