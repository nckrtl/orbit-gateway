<?php

declare(strict_types=1);

namespace App\Infrastructure\Activity;

use App\Models\App as OrbitApp;
use App\Models\Instance;
use App\Models\Node;
use App\Models\Workspace;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;

final readonly class CommandActivityTargetResolver
{
    /** @return array{subject_type: string, subject_id: int, target_node_id: ?int}|null */
    public function resolve(Request $request): ?array
    {
        $subject = $this->subject($request);

        if (! $subject instanceof Model) {
            return null;
        }

        return [
            'subject_type' => $subject->getMorphClass(),
            'subject_id' => (int) $subject->getKey(),
            'target_node_id' => $this->targetNodeId($subject),
        ];
    }

    private function subject(Request $request): ?Model
    {
        foreach (['workspace', 'instance', 'app', 'node'] as $parameter) {
            $model = $request->route($parameter);

            if ($model instanceof Model) {
                return $model;
            }
        }

        return match ($request->route()?->getName()) {
            'app:new' => OrbitApp::query()->where('slug', $request->input('slug'))->first(),
            'instance:new' => Instance::query()
                ->where('app_id', $request->integer('app_id'))
                ->where('node_id', $request->integer('node_id'))
                ->first(),
            'workspace:new' => Workspace::query()
                ->where('instance_id', $request->integer('instance_id'))
                ->where('name', $request->input('name'))
                ->first(),
            default => null,
        };
    }

    private function targetNodeId(Model $subject): ?int
    {
        if ($subject instanceof Node) {
            return $subject->id;
        }

        if ($subject instanceof Instance) {
            return $subject->node_id;
        }

        if (! $subject instanceof Workspace) {
            return null;
        }

        return $subject->instance()->first()?->node_id;
    }
}
