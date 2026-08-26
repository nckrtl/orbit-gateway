<?php

declare(strict_types=1);

namespace App\Actions\Nodes;

use App\Data\Nodes\NodeAccessNodeData;
use App\Data\Nodes\RemovedNodeAccessData;
use App\Domain\Nodes\NodeAccessAuthorizer;
use App\Domain\Shared\LifecycleStatus;
use App\Models\Node;
use App\Models\NodeAccess;
use Illuminate\Database\Eloquent\ModelNotFoundException;

final readonly class RemoveNodeAccessAction
{
    public function __construct(
        private NodeAccessAuthorizer $access,
    ) {}

    public function execute(Node $consumer, Node $serving, Node $caller): RemovedNodeAccessData
    {
        $this->requireActive($consumer);
        $this->requireActive($serving);

        $wasDeleted = NodeAccess::query()
            ->where('consumer_node_id', $consumer->id)
            ->where('serving_node_id', $serving->id)
            ->delete() === 1;
        $selfLockout = $wasDeleted && $caller->is($consumer) && $this->access->isGatewayNode($serving);

        return new RemovedNodeAccessData(
            consumerNode: NodeAccessNodeData::fromModel($consumer),
            servingNode: NodeAccessNodeData::fromModel($serving),
            alreadyAbsent: ! $wasDeleted,
            selfLockout: $selfLockout,
        );
    }

    private function requireActive(Node $node): void
    {
        if ($node->status !== LifecycleStatus::Active) {
            throw new ModelNotFoundException()->setModel(Node::class, [$node->id]);
        }
    }
}
