<?php

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Actions\Processes\AddProcessAction;
use App\Actions\Processes\ListProcessesAction;
use App\Actions\Processes\RemoveProcessAction;
use App\Actions\Processes\RestartProcessAction;
use App\Actions\Processes\ShowProcessLogsAction;
use App\Actions\Processes\StartProcessAction;
use App\Actions\Processes\StopProcessAction;
use App\Data\Processes\ProcessData;
use App\Domain\Processes\ProcessRuntimeManager;
use App\Http\Controllers\Controller;
use App\Http\Requests\Processes\ListProcessesRequest;
use App\Http\Requests\Processes\ProcessLogsRequest;
use App\Http\Requests\Processes\StoreProcessRequest;
use App\Models\Process;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use SensitiveParameter;

final class ProcessesController extends Controller
{
    public function index(ListProcessesRequest $request, ListProcessesAction $action): JsonResponse
    {
        return response()->json([
            'data' => $action->execute($request->targetType(), $request->targetId())->all(),
            'meta' => $this->meta($request),
        ]);
    }

    public function store(
        #[SensitiveParameter]
        StoreProcessRequest $request,
        AddProcessAction $action,
        ProcessRuntimeManager $runtime,
    ): JsonResponse {
        $result = $action->execute($request->payload());

        return response()->json(
            [
                'data' => ProcessData::fromModel(
                    $result['process'],
                    $runtime->status($result['process']),
                )->toArray(),
                'meta' => $this->meta($request),
            ],
            $result['created'] ? 201 : 200,
        );
    }

    public function start(
        Request $request,
        #[SensitiveParameter]
        Process $process,
        StartProcessAction $action,
        ProcessRuntimeManager $runtime,
    ): JsonResponse {
        return $this->processResponse($request, $action->execute($process), $runtime);
    }

    public function stop(
        Request $request,
        #[SensitiveParameter]
        Process $process,
        StopProcessAction $action,
        ProcessRuntimeManager $runtime,
    ): JsonResponse {
        return $this->processResponse($request, $action->execute($process), $runtime);
    }

    public function restart(
        Request $request,
        #[SensitiveParameter]
        Process $process,
        RestartProcessAction $action,
        ProcessRuntimeManager $runtime,
    ): JsonResponse {
        return $this->processResponse($request, $action->execute($process), $runtime);
    }

    public function logs(
        ProcessLogsRequest $request,
        #[SensitiveParameter]
        Process $process,
        ShowProcessLogsAction $action,
    ): JsonResponse {
        $lines = $request->lines();

        return response()->json([
            'data' => [
                'id' => $process->id,
                'name' => $process->name,
                'lines' => $lines,
                'logs' => $action->execute($process, $lines),
            ],
            'meta' => $this->meta($request),
        ]);
    }

    public function destroy(
        Request $request,
        #[SensitiveParameter]
        Process $process,
        RemoveProcessAction $action,
    ): JsonResponse {
        $data = ProcessData::fromModel($process, 'absent')->toArray();
        $action->execute($process);

        return response()->json([
            'data' => $data,
            'meta' => $this->meta($request),
        ]);
    }

    private function processResponse(
        Request $request,
        #[SensitiveParameter]
        Process $process,
        ProcessRuntimeManager $runtime,
    ): JsonResponse {
        return response()->json([
            'data' => ProcessData::fromModel($process, $runtime->status($process))->toArray(),
            'meta' => $this->meta($request),
        ]);
    }

    /** @return array{request_id: string} */
    private function meta(Request $request): array
    {
        return ['request_id' => $request->attributes->getString('orbit.request_id')];
    }
}
