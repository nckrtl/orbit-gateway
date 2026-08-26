<?php

declare(strict_types=1);

namespace App\Http\Authorization;

use Attribute;

#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD)]
final readonly class RequiresNodeAccess
{
    public function __construct(
        public ServingNode $servingNode,
    ) {}
}
