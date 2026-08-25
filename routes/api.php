<?php

declare(strict_types=1);

use App\Http\Controllers\Api\AppsController;
use App\Http\Controllers\Api\GatewayStatusesController;
use App\Http\Controllers\Api\InstancesController;
use App\Http\Controllers\Api\NodesController;
use App\Http\Controllers\Api\WorkspacesController;
use App\Http\Middleware\RequireActiveWireGuardPeer;
use Illuminate\Support\Facades\Route;

Route::prefix('v1')->group(function (): void {
    Route::get('gateway/status', [GatewayStatusesController::class, 'show'])
        ->name('gateway:status');
    Route::get('nodes', [NodesController::class, 'index'])
        ->name('node.list');
    Route::get('nodes/{node}', [NodesController::class, 'show'])
        ->name('node.show');
    Route::get('apps', [AppsController::class, 'index'])->name('app:list');
    Route::get('apps/{app}', [AppsController::class, 'show'])->name('app:show');

    Route::get('instances', [InstancesController::class, 'index'])->name('instance:list');
    Route::get('instances/{instance}', [InstancesController::class, 'show'])->name('instance:show');

    Route::get('workspaces', [WorkspacesController::class, 'index'])->name('workspace:list');
    Route::get('workspaces/{workspace}', [WorkspacesController::class, 'show'])
        ->name('workspace:show');

    Route::middleware(RequireActiveWireGuardPeer::class)->group(function (): void {
        Route::post('nodes', [NodesController::class, 'store'])
            ->name('node:provision');
        Route::post('apps', [AppsController::class, 'store'])->name('app:new');
        Route::delete('apps/{app}', [AppsController::class, 'destroy'])->name('app:remove');
        Route::post('instances', [InstancesController::class, 'store'])->name('instance:new');
        Route::delete('instances/{instance}', [InstancesController::class, 'destroy'])
            ->name('instance:remove');
        Route::patch('instances/{instance}/php', [InstancesController::class, 'php'])
            ->name('instance:php');
        Route::post('workspaces', [WorkspacesController::class, 'store'])->name('workspace:new');
        Route::delete('workspaces/{workspace}', [WorkspacesController::class, 'destroy'])
            ->name('workspace:remove');
        Route::patch('workspaces/{workspace}/php', [WorkspacesController::class, 'php'])
            ->name('workspace:php');
    });
});
