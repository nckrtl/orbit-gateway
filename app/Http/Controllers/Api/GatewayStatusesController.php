<?php

declare(strict_types=1);

namespace App\Http\Controllers\Api;

use App\Actions\Gateway\ShowGatewayStatusAction;
use App\Http\Controllers\Controller;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class GatewayStatusesController extends Controller
{
    public function show(Request $request, ShowGatewayStatusAction $action): JsonResponse
    {
        return response()->json([
            'data' => $action->handle()->toArray(),
            'meta' => [
                'request_id' => $request->attributes->getString('orbit.request_id'),
            ],
        ]);
    }
}
