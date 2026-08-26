<?php

declare(strict_types=1);

namespace App\Infrastructure\Firewall;

enum UfwRuleOwnership
{
    case Missing;
    case Exact;
    case Drift;
}
