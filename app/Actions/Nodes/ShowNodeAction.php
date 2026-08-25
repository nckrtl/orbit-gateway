<?php

declare(strict_types=1);

namespace App\Actions\Nodes;

use App\Models\Node;

final readonly class ShowNodeAction
{
    public function handle(Node $node): Node
    {
        return $node->load('roles');
    }
}
