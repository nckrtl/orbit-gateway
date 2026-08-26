<?php

declare(strict_types=1);

use App\Http\Controllers\Api\ActivitiesController;
use App\Http\Controllers\Api\AppsController;
use App\Http\Controllers\Api\FirewallRulesController;
use App\Http\Controllers\Api\GatewayStatusesController;
use App\Http\Controllers\Api\InstancesController;
use App\Http\Controllers\Api\NodesController;
use App\Http\Controllers\Api\ProcessesController;
use App\Http\Controllers\Api\RootCaCertificatesController;
use App\Http\Controllers\Api\WorkspacesController;
use App\Http\Middleware\RequireActiveWireGuardPeer;
use Illuminate\Support\Facades\Route;

Route::prefix('v1')->group(function (): void {
    Route::get('gateway/status', [GatewayStatusesController::class, 'show'])
        ->name('gateway:status');
    Route::get('ca/root', [RootCaCertificatesController::class, 'show'])
        ->name('gateway:trust');

    Route::middleware(RequireActiveWireGuardPeer::class)->group(function (): void {
        Route::get('nodes', [NodesController::class, 'index'])
            ->name('node:list');
        Route::get('nodes/{node}', [NodesController::class, 'show'])
            ->name('node:show');
        Route::get('nodes/{node}/firewall-rules', [FirewallRulesController::class, 'index'])
            ->name('firewall:list');
        Route::get('activities', [ActivitiesController::class, 'index'])
            ->name('activity:list');
        Route::get('activities/{activity}', [ActivitiesController::class, 'show'])
            ->name('activity:show');
        Route::post('nodes', [NodesController::class, 'store'])
            ->name('node:provision');
        Route::delete('nodes/{node}', [NodesController::class, 'destroy'])
            ->name('node:remove');
        Route::post('nodes/{node}/firewall-rules/allow', [FirewallRulesController::class, 'store'])
            ->defaults('firewall_action', 'allow')
            ->name('firewall:allow');
        Route::post('nodes/{node}/firewall-rules/deny', [FirewallRulesController::class, 'store'])
            ->defaults('firewall_action', 'deny')
            ->name('firewall:deny');
        Route::delete(
            'nodes/{node}/firewall-rules/{firewallRule:name}',
            [FirewallRulesController::class, 'destroy'],
        )
            ->scopeBindings()
            ->name('firewall:remove');
        Route::get('apps', [AppsController::class, 'index'])->name('app:list');
        Route::get('apps/{app}', [AppsController::class, 'show'])->name('app:show');
        Route::post('apps', [AppsController::class, 'store'])->name('app:new');
        Route::delete('apps/{app}', [AppsController::class, 'destroy'])->name('app:remove');
        Route::get('instances', [InstancesController::class, 'index'])->name('instance:list');
        Route::get('instances/{instance}', [InstancesController::class, 'show'])->name('instance:show');
        Route::post('instances', [InstancesController::class, 'store'])->name('instance:new');
        Route::delete('instances/{instance}', [InstancesController::class, 'destroy'])
            ->name('instance:remove');
        Route::patch('instances/{instance}/php', [InstancesController::class, 'php'])
            ->name('instance:php');
        Route::get('workspaces', [WorkspacesController::class, 'index'])->name('workspace:list');
        Route::get('workspaces/{workspace}', [WorkspacesController::class, 'show'])
            ->name('workspace:show');
        Route::post('workspaces', [WorkspacesController::class, 'store'])->name('workspace:new');
        Route::delete('workspaces/{workspace}', [WorkspacesController::class, 'destroy'])
            ->name('workspace:remove');
        Route::patch('workspaces/{workspace}/php', [WorkspacesController::class, 'php'])
            ->name('workspace:php');
        Route::get('processes', [ProcessesController::class, 'index'])
            ->name('process:list');
        Route::get('processes/{process}/logs', [ProcessesController::class, 'logs'])
            ->name('process:logs');
        Route::post('processes', [ProcessesController::class, 'store'])
            ->name('process:add');
        Route::post('processes/{process}/start', [ProcessesController::class, 'start'])
            ->name('process:start');
        Route::post('processes/{process}/stop', [ProcessesController::class, 'stop'])
            ->name('process:stop');
        Route::post('processes/{process}/restart', [ProcessesController::class, 'restart'])
            ->name('process:restart');
        Route::delete('processes/{process}', [ProcessesController::class, 'destroy'])
            ->name('process:remove');
    });
});
