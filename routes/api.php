<?php

declare(strict_types=1);

use App\Http\Controllers\Api\GatewayStatusesController;
use Illuminate\Support\Facades\Route;

Route::prefix('v1')->group(function (): void {
    Route::get('gateway/status', [GatewayStatusesController::class, 'show'])
        ->name('gateway:status');
});
