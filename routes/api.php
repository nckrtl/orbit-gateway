<?php

declare(strict_types=1);

use App\Http\Controllers\Api\GatewayStatusesController;
use App\Http\Controllers\Api\NodesController;
use Illuminate\Support\Facades\Route;

Route::prefix('v1')->group(function (): void {
    Route::get('gateway/status', [GatewayStatusesController::class, 'show'])
        ->name('gateway:status');
    Route::post('nodes', [NodesController::class, 'store'])
        ->name('node:provision');
});
