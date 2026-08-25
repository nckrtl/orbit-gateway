<?php

declare(strict_types=1);

use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\Nodes\NodeProvisioningException;
use App\Domain\Nodes\RoleAssignmentException;
use App\Domain\Shared\ResourceOperationException;
use App\Http\Middleware\EnsureRequestId;
use App\Http\Middleware\RecordCommandActivity;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        api: __DIR__.'/../routes/api.php',
        health: '/up',
    )
    ->withCommands()
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->api(prepend: [EnsureRequestId::class, RecordCommandActivity::class]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $notFound = static function (Request $request): JsonResponse {
            $requestId = $request->attributes->get('orbit.request_id');

            if (! is_string($requestId) || $requestId === '') {
                $requestId = $request->header('X-Orbit-Request-Id', '');
            }

            return response()
                ->json([
                    'error' => [
                        'code' => 'http.404',
                        'message' => 'Resource not found.',
                        'details' => [],
                    ],
                ], 404)
                ->header('X-Orbit-Request-Id', is_string($requestId) ? $requestId : '');
        };

        $exceptions->render(function (ValidationException $exception, Request $request): JsonResponse {
            $requestId = $request->attributes->get('orbit.request_id');

            if (! is_string($requestId) || $requestId === '') {
                $requestId = $request->header('X-Orbit-Request-Id', '');
            }

            return response()
                ->json([
                    'error' => [
                        'code' => 'validation.failed',
                        'message' => 'The request data is invalid.',
                        'details' => $exception->errors(),
                    ],
                ], 422)
                ->header('X-Orbit-Request-Id', is_string($requestId) ? $requestId : '');
        });
        $exceptions->render(function (NodeProvisioningException $exception, Request $request): JsonResponse {
            $request->attributes->set('orbit.error_code', $exception->errorCode);
            $request->attributes->set('orbit.command_result', $exception->result);
            $requestId = $request->attributes->get('orbit.request_id');

            if (! is_string($requestId) || $requestId === '') {
                $requestId = $request->header('X-Orbit-Request-Id', '');
            }

            return response()
                ->json([
                    'error' => [
                        'code' => $exception->errorCode,
                        'message' => $exception->getMessage(),
                        'details' => ['step' => $exception->step],
                    ],
                ], 502)
                ->header('X-Orbit-Request-Id', is_string($requestId) ? $requestId : '');
        });
        $exceptions->render(function (RuntimeConvergenceException $exception, Request $request): JsonResponse {
            $request->attributes->set('orbit.error_code', $exception->errorCode);
            $request->attributes->set('orbit.command_result', $exception->result);
            $requestId = $request->attributes->get('orbit.request_id');

            if (! is_string($requestId) || $requestId === '') {
                $requestId = $request->header('X-Orbit-Request-Id', '');
            }

            return response()
                ->json([
                    'error' => [
                        'code' => $exception->errorCode,
                        'message' => $exception->getMessage(),
                        'details' => ['step' => $exception->step],
                    ],
                ], 502)
                ->header('X-Orbit-Request-Id', is_string($requestId) ? $requestId : '');
        });
        $exceptions->render(function (ResourceOperationException $exception, Request $request): JsonResponse {
            $request->attributes->set('orbit.error_code', $exception->errorCode);
            $requestId = $request->attributes->get('orbit.request_id');

            if (! is_string($requestId) || $requestId === '') {
                $requestId = $request->header('X-Orbit-Request-Id', '');
            }

            return response()
                ->json([
                    'error' => [
                        'code' => $exception->errorCode,
                        'message' => $exception->getMessage(),
                        'details' => [],
                    ],
                ], $exception->status)
                ->header('X-Orbit-Request-Id', is_string($requestId) ? $requestId : '');
        });
        $exceptions->render(function (RoleAssignmentException $exception, Request $request): JsonResponse {
            $requestId = $request->attributes->get('orbit.request_id');

            if (! is_string($requestId) || $requestId === '') {
                $requestId = $request->header('X-Orbit-Request-Id', '');
            }

            return response()
                ->json([
                    'error' => [
                        'code' => 'node.role_conflict',
                        'message' => $exception->getMessage(),
                        'details' => [],
                    ],
                ], 422)
                ->header('X-Orbit-Request-Id', is_string($requestId) ? $requestId : '');
        });
        $exceptions->render(function (ModelNotFoundException $exception, Request $request) use (
            $notFound,
        ): JsonResponse {
            return $notFound($request);
        });
        $exceptions->render(function (NotFoundHttpException $exception, Request $request) use (
            $notFound,
        ): JsonResponse {
            return $notFound($request);
        });
        $exceptions->render(function (Throwable $exception, Request $request): ?JsonResponse {
            if (! $request->is('api/*')) {
                return null;
            }

            $request->attributes->set('orbit.error_code', 'gateway.unhandled');
            $requestId = $request->attributes->get('orbit.request_id');

            if (! is_string($requestId) || $requestId === '') {
                $requestId = $request->header('X-Orbit-Request-Id', '');
            }

            return response()
                ->json([
                    'error' => [
                        'code' => 'gateway.unhandled',
                        'message' => 'The gateway could not complete the request.',
                        'details' => [],
                    ],
                ], 500)
                ->header('X-Orbit-Request-Id', is_string($requestId) ? $requestId : '');
        });
        $exceptions->shouldRenderJsonWhen(
            fn (Request $request) => $request->is('api/*') || $request->expectsJson(),
        );
    })
    ->create();
