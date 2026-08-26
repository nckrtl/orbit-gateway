<?php

declare(strict_types=1);

namespace App\Http\Authorization;

use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Models\App as OrbitApp;
use App\Models\Instance;
use App\Models\Node;
use App\Models\Process;
use App\Models\Workspace;
use Illuminate\Http\Request;

/**
 * @mago-expect lint:cyclomatic-complexity Each serving scope has one explicit resolution path.
 * @mago-expect lint:kan-defect The cohesive resolver keeps route vocabulary and 404/422 boundaries together.
 */
final readonly class ServingNodeResolver
{
    /** @return list<Node> */
    public function resolve(Request $request, ServingNode $scope): array
    {
        return match ($scope) {
            ServingNode::Gateway => $this->gateway(),
            ServingNode::Target => $this->target($request),
            ServingNode::AppOwning => $this->appOwning($request),
            ServingNode::InstanceOwning => $this->instanceOwning($request),
            ServingNode::WorkspaceOwning => $this->workspaceOwning($request),
            ServingNode::ProcessOwning => $this->processOwning($request),
            ServingNode::Collection => [],
        };
    }

    /** @return list<Node> */
    private function gateway(): array
    {
        $gateway = Node::query()
            ->where('status', LifecycleStatus::Active)
            ->whereHas('roles', static function ($query): void {
                $query
                    ->where('role', RoleName::Gateway)
                    ->where('status', LifecycleStatus::Active);
            })
            ->orderBy('id')
            ->first();

        if (! $gateway instanceof Node) {
            throw new ActiveGatewayMissing('An active Gateway node is required.');
        }

        return [$gateway];
    }

    /** @return list<Node> */
    private function target(Request $request): array
    {
        foreach (['node', 'servingNode'] as $parameter) {
            $node = $request->route($parameter);

            if ($node instanceof Node) {
                return [$node];
            }
        }

        return [];
    }

    /** @return list<Node> */
    private function appOwning(Request $request): array
    {
        $app = $request->route('app');

        if (! $app instanceof OrbitApp) {
            $appId = $this->positiveInteger($request->input('app_id'));

            if ($appId === null) {
                return [];
            }

            $app = OrbitApp::query()->findOrFail($appId);
        }

        /** @var list<Node> $nodes */
        $nodes = Node::query()
            ->whereIn('id', $app->instances()->select('node_id'))
            ->orderBy('id')
            ->get()
            ->all();

        if ($nodes !== []) {
            return $nodes;
        }

        return $this->gateway();
    }

    /** @return list<Node> */
    private function instanceOwning(Request $request): array
    {
        $instance = $request->route('instance');

        if ($instance instanceof Instance) {
            return [Node::query()->findOrFail($instance->node_id)];
        }

        $nodeId = $this->positiveInteger($request->input('node_id'));

        if ($nodeId === null) {
            return [];
        }

        return [Node::query()->findOrFail($nodeId)];
    }

    /** @return list<Node> */
    private function workspaceOwning(Request $request): array
    {
        $workspace = $request->route('workspace');

        if ($workspace instanceof Workspace) {
            $instance = Instance::query()->findOrFail($workspace->instance_id);

            return [Node::query()->findOrFail($instance->node_id)];
        }

        $instanceId = $this->positiveInteger($request->input('instance_id'));

        if ($instanceId === null) {
            return [];
        }

        $instance = Instance::query()->findOrFail($instanceId);

        return [Node::query()->findOrFail($instance->node_id)];
    }

    /**
     * @mago-expect analysis:mixed-assignment Request input is an untyped boundary.
     * @return list<Node>
     */
    private function processOwning(Request $request): array
    {
        $process = $request->route('process');

        if ($process instanceof Process) {
            return [$this->ownerNode($process->owner)];
        }

        $targetType = $request->input('target_type');
        $targetId = $this->positiveInteger($request->input('target_id'));

        if (! is_string($targetType) || $targetId === null) {
            return [];
        }

        $owner = match ($targetType) {
            'instance' => Instance::query()->findOrFail($targetId),
            'workspace' => Workspace::query()->findOrFail($targetId),
            default => null,
        };

        if (! $owner instanceof Instance && ! $owner instanceof Workspace) {
            return [];
        }

        return [$this->ownerNode($owner)];
    }

    private function ownerNode(Instance|Workspace $owner): Node
    {
        if ($owner instanceof Instance) {
            return Node::query()->findOrFail($owner->node_id);
        }

        $instance = Instance::query()->findOrFail($owner->instance_id);

        return Node::query()->findOrFail($instance->node_id);
    }

    private function positiveInteger(mixed $value): ?int
    {
        if (is_int($value)) {
            return $value > 0 ? $value : null;
        }

        if (! is_string($value) || preg_match('/\A[1-9][0-9]*\z/D', $value) !== 1) {
            return null;
        }

        $integer = filter_var($value, FILTER_VALIDATE_INT);

        return is_int($integer) ? $integer : null;
    }
}
