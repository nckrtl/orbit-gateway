<?php

declare(strict_types=1);

namespace App\Infrastructure\Nodes;

use App\Domain\Instances\CertificateMode;
use App\Domain\Nodes\NodeRoleDependencyInspector;
use App\Domain\Nodes\NodeRoleDependencySet;
use App\Domain\Nodes\RoleName;
use App\Models\Instance;
use App\Models\Node;
use App\Models\Process;
use App\Models\Workspace;
use Illuminate\Database\Eloquent\Builder;

final readonly class EloquentNodeRoleDependencyInspector implements NodeRoleDependencyInspector
{
    public function inspect(Node $node, RoleName $role): NodeRoleDependencySet
    {
        $certificateMode = match ($role) {
            RoleName::AppDev => CertificateMode::OrbitCa,
            RoleName::AppProd => CertificateMode::Acme,
            default => null,
        };

        if (! $certificateMode instanceof CertificateMode) {
            return new NodeRoleDependencySet([], [], [], []);
        }

        /** @var list<int> $instanceIds */
        $instanceIds = Instance::query()
            ->where('node_id', $node->id)
            ->where('certificate_mode', $certificateMode)
            ->orderBy('id')
            ->pluck('id')
            ->all();
        /** @var list<int> $workspaceIds */
        $workspaceIds = $role === RoleName::AppDev
            ? Workspace::query()->whereIn('instance_id', $instanceIds)->orderBy('id')->pluck('id')->all()
            : [];
        /** @var list<int> $processIds */
        $processIds = Process::query()
            ->where(static function (Builder $query) use ($instanceIds, $workspaceIds): void {
                $query->where(static function (Builder $query) use ($instanceIds): void {
                    $query->where('owner_type', Instance::class)
                        ->whereIn('owner_id', $instanceIds);
                });

                if ($workspaceIds !== []) {
                    $query->orWhere(static function (Builder $query) use ($workspaceIds): void {
                        $query->where('owner_type', Workspace::class)
                            ->whereIn('owner_id', $workspaceIds);
                    });
                }
            })
            ->orderBy('id')
            ->pluck('id')
            ->all();
        $summaries = array_values(array_filter([
            $this->summary(
                count($instanceIds),
                $role === RoleName::AppDev
                    ? 'development instance record'
                    : 'production instance record',
            ),
            $this->summary(count($workspaceIds), 'workspace record'),
            $this->summary(count($processIds), 'process record'),
        ]));
        sort($summaries, SORT_STRING);

        return new NodeRoleDependencySet($instanceIds, $workspaceIds, $processIds, $summaries);
    }

    private function summary(int $count, string $singular): ?string
    {
        if ($count === 0) {
            return null;
        }

        return $count.' '.$singular.($count === 1 ? '' : 's');
    }
}
