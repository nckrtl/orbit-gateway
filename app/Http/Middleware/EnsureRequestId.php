<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;

final class EnsureRequestId
{
    public function handle(Request $request, Closure $next): Response
    {
        $requestId = $request->header('X-Orbit-Request-Id');

        if (! is_string($requestId) || ! Str::isUuid($requestId)) {
            $requestId = (string) Str::uuid();
        }

        $request->attributes->set('orbit.request_id', $requestId);

        /** @var Response $response */
        $response = $next($request);
        $response->headers->set('X-Orbit-Request-Id', $requestId);

        return $response;
    }
}
