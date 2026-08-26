<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\Firewall\FirewallOperationException;
use App\Domain\Nodes\NodeProvisioningException;
use App\Domain\Nodes\NodeRemovalException;
use App\Domain\Nodes\RoleAssignmentException;
use App\Domain\Processes\ProcessOperationException;
use App\Domain\Shared\ResourceOperationException;
use App\Infrastructure\Activity\CommandActivityInputSanitizer;
use App\Infrastructure\Activity\CommandActivityTargetResolver;
use App\Infrastructure\Http\TopLevelJsonObjectInspector;
use App\Infrastructure\Processes\CommandDeadline;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\WireGuard\WireGuardPeerAddressResolver;
use App\Models\Activity;
use App\Models\Node;
use App\Models\Process;
use Closure;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Illuminate\Validation\ValidationException;
use InvalidArgumentException;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Throwable;

/**
 * @mago-expect lint:cyclomatic-complexity Command activity maps each bounded domain failure explicitly.
 * @mago-expect lint:kan-defect Command activity maps each bounded domain failure explicitly.
 * @mago-expect lint:too-many-methods Command activity keeps one attempt lifecycle in one middleware.
 */
final readonly class RecordCommandActivity
{
    public function __construct(
        private CommandDeadline $deadline,
        private CommandActivityInputSanitizer $inputSanitizer,
        private CommandActivityTargetResolver $targetResolver,
        private WireGuardPeerAddressResolver $addresses,
        private TopLevelJsonObjectInspector $jsonInspector,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $this->deadline->start(Config::float('orbit.command_timeout', 900.0));

        try {
            return $this->record($request, $next);
        } finally {
            $this->deadline->clear();
        }
    }

    private function record(Request $request, Closure $next): Response
    {
        $startedAt = microtime(true);
        $activity = $this->start($request);

        try {
            $this->recordInput($activity, $request);
            /** @var Response $response */
            $response = $next($request);
            $this->complete($activity, $request, $response->getStatusCode(), $startedAt);

            return $response;
        } catch (Throwable $exception) {
            $this->fail($activity, $request, $exception, $startedAt);

            throw $exception;
        }
    }

    /** @mago-expect analysis:mixed-assignment Request attributes are an untyped boundary. */
    private function start(Request $request): Activity
    {
        $requestId = $request->attributes->get('orbit.request_id');
        $command = $request->route()->getName();
        $callerIp = $this->callerIp($request);

        return Activity::query()->create([
            'log_name' => 'commands',
            'description' => is_string($command) ? $command : 'unknown',
            'event' => 'command',
            'properties' => [
                'method' => $request->method(),
                'path' => $request->path(),
                'input' => [],
            ],
            'request_id' => is_string($requestId) ? $requestId : '',
            'command' => is_string($command) ? $command : 'unknown',
            'caller_node_id' => $this->callerNodeId($callerIp, is_string($command) ? $command : null),
            'caller_ip' => $callerIp,
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

        $activity->update($this->withTarget(
            $activity,
            $request,
            $this->withResult($activity, $request, $updates, $commandResult),
        ));
    }

    private function fail(
        Activity $activity,
        Request $request,
        Throwable $exception,
        float $startedAt,
    ): void {
        $updates = [
            'status' => 'failed',
            'duration_ms' => $this->duration($startedAt),
            'error_code' => match (true) {
                $exception instanceof ValidationException => 'validation.failed',
                $exception instanceof NodeProvisioningException => $exception->errorCode,
                $exception instanceof NodeRemovalException => $exception->errorCode,
                $exception instanceof RuntimeConvergenceException => $exception->errorCode,
                $exception instanceof ProcessOperationException => $exception->errorCode,
                $exception instanceof FirewallOperationException => $exception->errorCode,
                $exception instanceof ResourceOperationException => $exception->errorCode,
                $exception instanceof RoleAssignmentException => 'node.role_conflict',
                $exception instanceof ModelNotFoundException, $exception instanceof NotFoundHttpException => 'http.404',
                default => 'gateway.unhandled',
            },
        ];
        $result = match (true) {
            $exception instanceof NodeProvisioningException => $exception->result,
            $exception instanceof NodeRemovalException => $exception->result,
            $exception instanceof RuntimeConvergenceException => $exception->result,
            $exception instanceof ProcessOperationException => $exception->result,
            $exception instanceof FirewallOperationException => $exception->result,
            default => null,
        };

        $activity->update($this->withTarget(
            $activity,
            $request,
            $this->withResult($activity, $request, $updates, $result),
        ));
    }

    /**
     * @param array<string, mixed> $updates
     *
     * @return array<string, mixed>
     */
    private function withResult(
        Activity $activity,
        Request $request,
        array $updates,
        mixed $result,
    ): array {
        if (! $result instanceof CommandResult) {
            return $updates;
        }

        return [
            ...$updates,
            'exit_code' => $result->exitCode,
            'properties' => [
                ...($activity->properties?->toArray() ?? []),
                'stdout' => $this->redact($request, $result->stdout),
                'stderr' => $this->redact($request, $result->stderr),
                'output_truncated' => $result->truncated,
            ],
        ];
    }

    private function callerNodeId(string $callerIp, ?string $command): ?int
    {
        $query = Node::query()->where('wireguard_address', $callerIp);

        if (
            in_array(
                needle: $command,
                haystack: ['node:setup:app-dev:script', 'node:setup:app-dev:result'],
                strict: true,
            )
        ) {
            $query
                ->where('platform', 'darwin')
                ->whereIn('status', ['provisioning', 'failed', 'active']);

            return $query->first()?->id;
        }

        return $query->where('status', 'active')->first()?->id;
    }

    private function callerIp(Request $request): string
    {
        return $this->addresses->resolve($request) ?? '';
    }

    private function recordInput(Activity $activity, Request $request): void
    {
        $command = $request->route()->getName();
        $allowedKeys = match ($command) {
            'node:role:add' => ['role'],
            'node:setup:app-dev:script' => ['platform', 'architecture', 'username', 'home_directory'],
            'node:setup:app-dev:result' => ['exit_code', 'diagnostics'],
            default => null,
        };

        if ($allowedKeys !== null) {
            try {
                $this->jsonInspector->inspect($request->getContent(), $allowedKeys);
            } catch (InvalidArgumentException) {
                throw ValidationException::withMessages([
                    'body' => ['The request body must be a JSON object with unique allowed keys.'],
                ]);
            }
        }

        $input = $request->collect()->all();
        $input = match ($command) {
            'node:setup:app-dev:script' => array_intersect_key($input, array_flip(['platform', 'architecture'])),
            'node:setup:app-dev:result' => $this->sanitizeSetupResultInput($input),
            default => $input,
        };
        $properties = $activity->properties?->toArray() ?? [];
        $activity->update([
            'properties' => [
                ...$properties,
                'input' => $this->inputSanitizer->sanitize($input),
            ],
        ]);
    }

    /**
     * @param array<array-key, mixed> $input
     * @return array<array-key, mixed>
     *
     * @mago-expect analysis:mixed-assignment Setup diagnostics are checked before sanitization.
     */
    private function sanitizeSetupResultInput(array $input): array
    {
        $diagnostics = $input['diagnostics'] ?? null;

        if (! is_string($diagnostics)) {
            unset($input['diagnostics']);
        }

        if (is_string($diagnostics)) {
            $input['diagnostics'] = $this->inputSanitizer->sanitizeDiagnostics($diagnostics);
        }

        return array_intersect_key($input, array_flip(['exit_code', 'diagnostics']));
    }

    private function duration(float $startedAt): int
    {
        return (int) round((microtime(true) - $startedAt) * 1_000);
    }

    private function errorCode(int $statusCode): string
    {
        return $statusCode === 422 ? 'validation.failed' : "http.{$statusCode}";
    }

    /**
     * @param array<string, mixed> $updates
     *
     * @return array<string, mixed>
     *
     * @mago-expect analysis:mixed-assignment Request attributes are an untyped transport boundary.
     */
    private function withTarget(Activity $activity, Request $request, array $updates): array
    {
        $target = $this->targetResolver->resolve($request);

        if ($target !== null) {
            $updates = [...$updates, ...$target];
        }

        $snapshot = $request->attributes->get('orbit.target_node_snapshot');

        if (
            ! is_array($snapshot)
            || ! is_int($snapshot['id'] ?? null)
            || ! is_string($snapshot['name'] ?? null)
        ) {
            return $updates;
        }

        /** @var array<string, mixed> $properties */
        $properties = is_array($updates['properties'] ?? null)
            ? $updates['properties']
            : $activity->properties?->toArray() ?? [];

        return [
            ...$updates,
            'properties' => [
                ...$properties,
                'target_node' => [
                    'id' => $snapshot['id'],
                    'name' => $snapshot['name'],
                ],
            ],
        ];
    }

    private function redact(Request $request, string $output): string
    {
        $redacted = $this->inputSanitizer->redactText($output);
        $values = $this->environmentSecretValues($request);

        return str_replace(search: $values, replace: '[REDACTED]', subject: $redacted);
    }

    /**
     * @return list<string>
     *
     * @mago-expect analysis:mixed-assignment Request and persisted JSON values are untyped transport boundaries.
     */
    private function environmentSecretValues(Request $request): array
    {
        $process = $request->route('process');
        $storedEnvironment = $process instanceof Process
            ? $process->runtime_config['environment'] ?? null
            : null;
        /** @var list<string> $values */
        $values = [];

        foreach ([$request->input('environment'), $storedEnvironment] as $environment) {
            if (! is_array($environment)) {
                continue;
            }

            foreach ($environment as $value) {
                if (! is_string($value) || $value === '') {
                    continue;
                }

                $values[] = $value;
            }
        }

        $values = array_values(array_unique($values));
        usort($values, static fn (string $first, string $second): int => strlen($second) <=> strlen($first));

        return $values;
    }
}
