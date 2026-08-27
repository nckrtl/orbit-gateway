<?php

declare(strict_types=1);

use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\Firewall\FirewallOperationException;
use App\Domain\Nodes\NodeProvisioningException;
use App\Domain\Nodes\NodeRemovalException;
use App\Domain\Nodes\NodeRoleOperationException;
use App\Domain\Nodes\NodeRoleValidationException;
use App\Domain\Nodes\RoleAssignmentException;
use App\Domain\Processes\ProcessOperationException;
use App\Domain\Shared\ResourceOperationException;
use App\Http\Middleware\EnsureRequestId;
use App\Http\Middleware\RecordCommandActivity;
use App\Http\Middleware\RequireActiveWireGuardPeer;
use App\Http\Middleware\RequireNodeAccess;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/** @mago-expect lint:no-ini-set Exception arguments must be disabled before Laravel handles input. */
if (
    ini_get('zend.exception_ignore_args') !== '1'
    && (! function_exists('ini_set')
    || ini_set(option: 'zend.exception_ignore_args', value: '1') === false
    || ini_get('zend.exception_ignore_args') !== '1')
) {
    throw new RuntimeException('PHP must omit arguments from exception traces.');
}

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        api: __DIR__.'/../routes/api.php',
        health: '/up',
    )
    ->withCommands()
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->api(prepend: [EnsureRequestId::class, RecordCommandActivity::class]);
        $middleware->prependToPriorityList(SubstituteBindings::class, RequireActiveWireGuardPeer::class);
        $middleware->appendToPriorityList(SubstituteBindings::class, RequireNodeAccess::class);
    })
    ->withExceptions(
        /**
         * @mago-expect lint:cyclomatic-complexity API exception types map to explicit stable envelopes.
         * @mago-expect lint:halstead The closure keeps the public error contract visible in bootstrap order.
         */
        function (Exceptions $exceptions): void {
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
            $exceptions->render(function (NodeRoleValidationException $exception, Request $request): JsonResponse {
                $request->attributes->set('orbit.error_code', 'validation.failed');
                $requestId = $request->attributes->get('orbit.request_id');

                if (! is_string($requestId) || $requestId === '') {
                    $requestId = $request->header('X-Orbit-Request-Id', '');
                }

                return response()
                    ->json([
                        'error' => [
                            'code' => 'validation.failed',
                            'message' => $exception->getMessage(),
                            'details' => $exception->details,
                        ],
                    ], 422)
                    ->header('X-Orbit-Request-Id', is_string($requestId) ? $requestId : '');
            });
            $exceptions->render(function (NodeRoleOperationException $exception, Request $request): JsonResponse {
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
            $exceptions->render(function (NodeRemovalException $exception, Request $request): JsonResponse {
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
            $exceptions->render(function (ProcessOperationException $exception, Request $request): JsonResponse {
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
            $exceptions->render(function (FirewallOperationException $exception, Request $request): JsonResponse {
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
                    ], $exception->status)
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
            $exceptions->render(
                fn (ModelNotFoundException $exception, Request $request): JsonResponse => $notFound($request),
            );
            $exceptions->render(
                fn (NotFoundHttpException $exception, Request $request): JsonResponse => $notFound($request),
            );
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
        },
    )
    ->create();
