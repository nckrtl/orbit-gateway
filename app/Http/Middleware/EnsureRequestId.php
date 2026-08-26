<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Symfony\Component\HttpFoundation\Response;

final class EnsureRequestId
{
    private const string PATTERN = '/\A[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/iD';

    public function handle(Request $request, Closure $next): Response
    {
        $requestId = $request->header('X-Orbit-Request-Id');

        if (! is_string($requestId) || preg_match(self::PATTERN, $requestId) !== 1) {
            $requestId = (string) Str::uuid();
        }

        $request->attributes->set('orbit.request_id', $requestId);

        /** @var Response $response */
        $response = $next($request);
        $response->headers->set('X-Orbit-Request-Id', $requestId);

        return $response;
    }
}
