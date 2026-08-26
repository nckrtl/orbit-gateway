<?php

declare(strict_types=1);

namespace App\Actions\Processes;

use App\Data\Processes\ProcessData;
use App\Domain\Processes\ProcessRuntimeManager;
use App\Domain\Processes\ProcessTargetType;
use App\Models\Process;
use Illuminate\Support\Collection;

final readonly class ListProcessesAction
{
    public function __construct(
        private ProcessRuntimeManager $runtime,
    ) {}

    /** @return Collection<int, array<string, mixed>> */
    public function execute(ProcessTargetType $targetType, int $targetId): Collection
    {
        $processes = Process::query()
            ->where('owner_type', $targetType->modelClass())
            ->where('owner_id', $targetId)
            ->orderBy('name')
            ->get();
        /** @var Collection<int, array<string, mixed>> $result */
        $result = new Collection;

        foreach ($processes as $process) {
            /** @var array<string, mixed> $data */
            $data = ProcessData::fromModel(
                $process,
                $this->runtime->status($process),
            )->toArray();
            $result->push($data);
        }

        return $result;
    }
}
