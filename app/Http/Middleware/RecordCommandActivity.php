<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use App\Models\Activity;
use App\Models\Node;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

final class RecordCommandActivity
{
    /** @mago-expect analysis:mixed-assignment Request attributes are an untyped boundary. */
    public function handle(Request $request, Closure $next): Response
    {
        $startedAt = microtime(true);
        $requestId = $request->attributes->get('orbit.request_id');
        $route = $request->route();
        $command = $route->getName();

        $activity = Activity::query()->create([
            'log_name' => 'commands',
            'description' => is_string($command) ? $command : 'unknown',
            'event' => 'command',
            'properties' => [
                'method' => $request->method(),
                'path' => $request->path(),
                'input' => $request->except(['password', 'private_key', 'secret', 'token']),
            ],
            'request_id' => is_string($requestId) ? $requestId : '',
            'command' => is_string($command) ? $command : 'unknown',
            'caller_node_id' => $this->callerNodeId($request),
            'caller_ip' => $request->ip(),
            'status' => 'running',
        ]);

        try {
            /** @var Response $response */
            $response = $next($request);
            $statusCode = $response->getStatusCode();

            $activity->update([
                'status' => $statusCode < 400 ? 'succeeded' : 'failed',
                'duration_ms' => $this->duration($startedAt),
                'error_code' => $statusCode < 400 ? null : $this->errorCode($statusCode),
            ]);

            return $response;
        } catch (Throwable $exception) {
            $activity->update([
                'status' => 'failed',
                'duration_ms' => $this->duration($startedAt),
                'error_code' => 'gateway.unhandled',
            ]);

            throw $exception;
        }
    }

    private function callerNodeId(Request $request): ?int
    {
        $node = Node::query()
            ->where('wireguard_address', $request->ip())
            ->where('status', 'active')
            ->first();

        return $node?->id;
    }

    private function duration(float $startedAt): int
    {
        return (int) round((microtime(true) - $startedAt) * 1_000);
    }

    private function errorCode(int $statusCode): string
    {
        return $statusCode === 422 ? 'validation.failed' : "http.{$statusCode}";
    }
}
