<?php

declare(strict_types=1);

use App\Http\Authorization\RequiresNodeAccess;
use App\Http\Authorization\ServingNode;
use App\Http\Middleware\RequireActiveWireGuardPeer;
use App\Http\Middleware\RequireNodeAccess;
use Illuminate\Routing\Route as IlluminateRoute;
use Illuminate\Support\Facades\Route;

it('declares node access scope on every active-peer API route', function (): void {
    $protectedRoutes = collect(Route::getRoutes()->getRoutes())
        ->filter(static fn (IlluminateRoute $route): bool => str_starts_with($route->uri(), 'api/v1/'))
        ->filter(
            static fn (IlluminateRoute $route): bool => in_array(
                RequireActiveWireGuardPeer::class,
                $route->gatherMiddleware(),
                strict: true,
            ),
        )
        ->values();

    expect($protectedRoutes)->not->toBeEmpty();

    $actualScopes = [];

    foreach ($protectedRoutes as $route) {
        expect($route->gatherMiddleware())
            ->toContain(RequireNodeAccess::class);

        $controllerClass = $route->getControllerClass();
        $method = $route->getActionMethod();

        expect($controllerClass)->toBeString();

        $classAttributes = new ReflectionClass($controllerClass)
            ->getAttributes(RequiresNodeAccess::class);
        $methodAttributes = new ReflectionMethod($controllerClass, $method)
            ->getAttributes(RequiresNodeAccess::class);

        expect(count($classAttributes) + count($methodAttributes))
            ->toBe(1, "Route [{$route->getName()}] must declare exactly one RequiresNodeAccess attribute.");

        $attribute = $methodAttributes[0] ?? $classAttributes[0];
        $actualScopes[$route->getName()] = $attribute->newInstance()->servingNode;
    }

    ksort($actualScopes);

    $expectedScopes = [
        'activity:list' => ServingNode::Gateway,
        'activity:show' => ServingNode::Gateway,
        'app:list' => ServingNode::Collection,
        'app:new' => ServingNode::Gateway,
        'app:remove' => ServingNode::AppOwning,
        'app:show' => ServingNode::AppOwning,
        'firewall:allow' => ServingNode::Target,
        'firewall:deny' => ServingNode::Target,
        'firewall:list' => ServingNode::Target,
        'firewall:remove' => ServingNode::Target,
        'instance:list' => ServingNode::Collection,
        'instance:new' => ServingNode::InstanceOwning,
        'instance:php' => ServingNode::InstanceOwning,
        'instance:remove' => ServingNode::InstanceOwning,
        'instance:show' => ServingNode::InstanceOwning,
        'node:access:add' => ServingNode::Gateway,
        'node:access:remove' => ServingNode::Gateway,
        'node:list' => ServingNode::Collection,
        'node:provision' => ServingNode::Gateway,
        'node:remove' => ServingNode::Target,
        'node:role:add' => ServingNode::Target,
        'node:role:list' => ServingNode::Target,
        'node:role:remove' => ServingNode::Target,
        'node:show' => ServingNode::Target,
        'process:add' => ServingNode::ProcessOwning,
        'process:list' => ServingNode::ProcessOwning,
        'process:logs' => ServingNode::ProcessOwning,
        'process:remove' => ServingNode::ProcessOwning,
        'process:restart' => ServingNode::ProcessOwning,
        'process:start' => ServingNode::ProcessOwning,
        'process:stop' => ServingNode::ProcessOwning,
        'workspace:list' => ServingNode::Collection,
        'workspace:new' => ServingNode::WorkspaceOwning,
        'workspace:php' => ServingNode::WorkspaceOwning,
        'workspace:remove' => ServingNode::WorkspaceOwning,
        'workspace:show' => ServingNode::WorkspaceOwning,
    ];

    expect($actualScopes)->toBe($expectedScopes);
});

it('keeps only bootstrap routes outside peer and node access middleware', function (): void {
    $apiRoutes = collect(Route::getRoutes()->getRoutes())
        ->filter(static fn (IlluminateRoute $route): bool => str_starts_with($route->uri(), 'api/v1/'))
        ->values();

    foreach ($apiRoutes as $route) {
        $middleware = $route->gatherMiddleware();

        if (in_array($route->getName(), ['gateway:status', 'gateway:trust'], strict: true)) {
            expect($middleware)
                ->not->toContain(RequireActiveWireGuardPeer::class)
                ->not->toContain(RequireNodeAccess::class);

            continue;
        }

        expect($middleware)
            ->toContain(RequireActiveWireGuardPeer::class)
            ->toContain(RequireNodeAccess::class);
    }

    expect($apiRoutes->map(static fn (IlluminateRoute $route): ?string => $route->getName())->all())
        ->toContain('gateway:status', 'gateway:trust');
});
