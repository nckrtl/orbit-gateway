<?php

declare(strict_types=1);

namespace App\Data\Activities;

use App\Infrastructure\Activity\CommandActivityInputSanitizer;
use App\Models\Activity;
use App\Models\App as OrbitApp;
use App\Models\FirewallRule;
use App\Models\Instance;
use App\Models\Node;
use App\Models\Process as OrbitProcess;
use App\Models\Workspace;
use DateTimeInterface;

/** @mago-expect lint:excessive-parameter-list */
final readonly class ActivityData
{
    /** @param array<string, mixed> $properties */
    public function __construct(
        public int $id,
        public string $requestId,
        public string $command,
        public ?int $callerNodeId,
        public ?int $targetNodeId,
        public ?string $callerIp,
        public string $status,
        public ?int $durationMs,
        public ?int $exitCode,
        public ?string $errorCode,
        public ?string $subjectType,
        public ?int $subjectId,
        public array $properties,
        public string $occurredAt,
    ) {}

    /** @mago-expect analysis:mixed-assignment Eloquent attributes are untyped until validated below. */
    public static function fromModel(Activity $activity): self
    {
        $callerNodeId = $activity->getAttribute('caller_node_id');
        $targetNodeId = $activity->getAttribute('target_node_id');
        $subjectType = $activity->getAttribute('subject_type');
        $subjectId = $activity->getAttribute('subject_id');
        $createdAt = $activity->getAttribute('created_at');

        return new self(
            id: (int) $activity->getKey(),
            requestId: $activity->request_id,
            command: $activity->command,
            callerNodeId: is_int($callerNodeId) ? $callerNodeId : null,
            targetNodeId: is_int($targetNodeId) ? $targetNodeId : null,
            callerIp: $activity->caller_ip,
            status: $activity->status,
            durationMs: $activity->duration_ms,
            exitCode: $activity->exit_code,
            errorCode: $activity->error_code,
            subjectType: self::publicSubjectType(is_string($subjectType) ? $subjectType : null),
            subjectId: is_int($subjectId) ? $subjectId : null,
            properties: self::properties($activity),
            occurredAt: $createdAt instanceof DateTimeInterface ? $createdAt->format(DateTimeInterface::ATOM) : '',
        );
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'request_id' => $this->requestId,
            'command' => $this->command,
            'caller_node_id' => $this->callerNodeId,
            'target_node_id' => $this->targetNodeId,
            'caller_ip' => $this->callerIp,
            'status' => $this->status,
            'duration_ms' => $this->durationMs,
            'exit_code' => $this->exitCode,
            'error_code' => $this->errorCode,
            'subject_type' => $this->subjectType,
            'subject_id' => $this->subjectId,
            'properties' => $this->properties,
            'occurred_at' => $this->occurredAt,
        ];
    }

    /**
     * @mago-expect analysis:mixed-assignment Activity properties are untyped until their keys are validated below.
     *
     * @return array<string, mixed>
     */
    private static function properties(Activity $activity): array
    {
        $properties = $activity->properties?->toArray() ?? [];
        $result = [];

        foreach ($properties as $key => $value) {
            if (! is_string($key)) {
                continue;
            }

            $result[$key] = $value;
        }

        $sanitized = new CommandActivityInputSanitizer()->sanitize($result);

        if (! is_array($sanitized)) {
            return [];
        }

        /** @var array<string, mixed> $sanitized */
        return $sanitized;
    }

    private static function publicSubjectType(?string $subjectType): ?string
    {
        return match ($subjectType) {
            Node::class => 'node',
            OrbitApp::class => 'app',
            Instance::class => 'instance',
            Workspace::class => 'workspace',
            OrbitProcess::class => 'process',
            FirewallRule::class => 'firewall_rule',
            default => null,
        };
    }
}
