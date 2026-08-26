<?php

declare(strict_types=1);

namespace App\Actions\Nodes;

use App\Data\Nodes\AddedNodeAccessData;
use App\Data\Nodes\NodeAccessNodeData;
use App\Domain\Shared\LifecycleStatus;
use App\Models\Node;
use App\Models\NodeAccess;
use Illuminate\Database\Eloquent\ModelNotFoundException;

final readonly class AddNodeAccessAction
{
    public function execute(Node $consumer, Node $serving): AddedNodeAccessData
    {
        $this->requireActive($consumer);
        $this->requireActive($serving);

        $access = NodeAccess::query()->firstOrCreate([
            'consumer_node_id' => $consumer->id,
            'serving_node_id' => $serving->id,
        ]);

        return new AddedNodeAccessData(
            consumerNode: NodeAccessNodeData::fromModel($consumer),
            servingNode: NodeAccessNodeData::fromModel($serving),
            alreadyExists: ! $access->wasRecentlyCreated,
        );
    }

    private function requireActive(Node $node): void
    {
        if ($node->status !== LifecycleStatus::Active) {
            throw new ModelNotFoundException()->setModel(Node::class, [$node->id]);
        }
    }
}
