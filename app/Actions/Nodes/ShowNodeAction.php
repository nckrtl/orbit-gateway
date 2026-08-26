<?php

declare(strict_types=1);

namespace App\Actions\Nodes;

use App\Models\Node;

final readonly class ShowNodeAction
{
    public function handle(Node $node): Node
    {
        $node->load('roles');
        $node->setRelation(
            'accessibleNodes',
            $node->accessibleNodes()->orderBy('nodes.id')->get(),
        );
        $node->setRelation(
            'accessingNodes',
            $node->accessingNodes()->orderBy('nodes.id')->get(),
        );

        return $node;
    }
}
