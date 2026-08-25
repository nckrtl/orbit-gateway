<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use App\Domain\Nodes\NodeProvisioningException;
use App\Infrastructure\Processes\CommandResult;
use App\Models\Activity;
use App\Models\Node;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

final class RecordCommandActivity
{
    public function handle(Request $request, Closure $next): Response
    {
        $startedAt = microtime(true);
        $activity = $this->start($request);

        try {
            /** @var Response $response */
            $response = $next($request);
            $this->complete($activity, $request, $response->getStatusCode(), $startedAt);

            return $response;
        } catch (Throwable $exception) {
            $this->fail($activity, $exception, $startedAt);

            throw $exception;
        }
    }

    /** @mago-expect analysis:mixed-assignment Request attributes are an untyped boundary. */
    private function start(Request $request): Activity
    {
        $requestId = $request->attributes->get('orbit.request_id');
        $command = $request->route()->getName();

        return Activity::query()->create([
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
    }

    /** @mago-expect analysis:mixed-assignment Request attributes are an untyped boundary. */
    private function complete(Activity $activity, Request $request, int $statusCode, float $startedAt): void
    {
        $requestErrorCode = $request->attributes->get('orbit.error_code');
        $commandResult = $request->attributes->get('orbit.command_result');
        $errorCode = null;

        if ($statusCode >= 400) {
            $errorCode = is_string($requestErrorCode) ? $requestErrorCode : $this->errorCode($statusCode);
        }

        $updates = [
            'status' => $statusCode < 400 ? 'succeeded' : 'failed',
            'duration_ms' => $this->duration($startedAt),
            'error_code' => $errorCode,
        ];

        $activity->update($this->withResult($activity, $updates, $commandResult));
    }

    private function fail(Activity $activity, Throwable $exception, float $startedAt): void
    {
        $updates = [
            'status' => 'failed',
            'duration_ms' => $this->duration($startedAt),
            'error_code' => match (true) {
                $exception instanceof ValidationException => 'validation.failed',
                $exception instanceof NodeProvisioningException => $exception->errorCode,
                default => 'gateway.unhandled',
            },
        ];
        $result = $exception instanceof NodeProvisioningException ? $exception->result : null;

        $activity->update($this->withResult($activity, $updates, $result));
    }

    /**
     * @param array<string, mixed> $updates
     *
     * @return array<string, mixed>
     */
    private function withResult(Activity $activity, array $updates, mixed $result): array
    {
        if (! $result instanceof CommandResult) {
            return $updates;
        }

        return [
            ...$updates,
            'exit_code' => $result->exitCode,
            'properties' => [
                ...($activity->properties?->toArray() ?? []),
                'stdout' => $this->redact($result->stdout),
                'stderr' => $this->redact($result->stderr),
                'output_truncated' => $result->truncated,
            ],
        ];
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

    private function redact(string $output): string
    {
        $redacted = preg_replace(
            pattern: '/(password|token|secret|private[_ -]?key)(\s*[=:]\s*)\S+/i',
            replacement: '$1$2[REDACTED]',
            subject: $output,
        );

        return is_string($redacted) ? $redacted : '';
    }
}
