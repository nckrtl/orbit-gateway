<?php

declare(strict_types=1);

use App\Domain\Nodes\NodeProvisioningException;
use App\Domain\Nodes\RoleAssignmentException;
use App\Http\Middleware\EnsureRequestId;
use App\Http\Middleware\RecordCommandActivity;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        api: __DIR__.'/../routes/api.php',
        health: '/up',
    )
    ->withCommands()
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->api(append: [EnsureRequestId::class, RecordCommandActivity::class]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->render(function (ValidationException $exception, Request $request): JsonResponse {
            return response()
                ->json([
                    'error' => [
                        'code' => 'validation.failed',
                        'message' => 'The request data is invalid.',
                        'details' => $exception->errors(),
                    ],
                ], 422)
                ->header('X-Orbit-Request-Id', (string) $request->attributes->get('orbit.request_id'));
        });
        $exceptions->render(function (NodeProvisioningException $exception, Request $request): JsonResponse {
            $request->attributes->set('orbit.error_code', $exception->errorCode);
            $request->attributes->set('orbit.command_result', $exception->result);

            return response()
                ->json([
                    'error' => [
                        'code' => $exception->errorCode,
                        'message' => $exception->getMessage(),
                        'details' => ['step' => $exception->step],
                    ],
                ], 502)
                ->header('X-Orbit-Request-Id', (string) $request->attributes->get('orbit.request_id'));
        });
        $exceptions->render(function (RoleAssignmentException $exception, Request $request): JsonResponse {
            return response()
                ->json([
                    'error' => [
                        'code' => 'node.role_conflict',
                        'message' => $exception->getMessage(),
                        'details' => [],
                    ],
                ], 422)
                ->header('X-Orbit-Request-Id', (string) $request->attributes->get('orbit.request_id'));
        });
        $exceptions->shouldRenderJsonWhen(
            fn (Request $request) => $request->is('api/*') || $request->expectsJson(),
        );
    })
    ->create();
