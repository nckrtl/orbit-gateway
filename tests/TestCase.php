<?php

declare(strict_types=1);

namespace Tests;

use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Models\Node;
use App\Models\NodeRole;
use Illuminate\Foundation\Testing\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{
    protected function markAsGateway(Node $node): Node
    {
        NodeRole::query()->updateOrCreate(
            ['node_id' => $node->id, 'role' => RoleName::Gateway],
            ['status' => LifecycleStatus::Active],
        );

        return $node->refresh();
    }
}
