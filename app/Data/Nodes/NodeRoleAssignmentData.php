<?php

declare(strict_types=1);

namespace App\Data\Nodes;

use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Models\NodeRole;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\SnakeCaseMapper;

#[MapOutputName(SnakeCaseMapper::class)]
final class NodeRoleAssignmentData extends Data
{
    /** @mago-expect lint:excessive-parameter-list API assignment data has six stable serialized fields. */
    public function __construct(
        public string $role,
        public string $status,
        public ?string $failedStep,
        public ?string $errorCode,
        public bool $localActionRequired,
        public ?string $localCommand,
    ) {}

    public static function fromModel(NodeRole $assignment): self
    {
        $assignment->loadMissing('node');
        $setupEligible =
            $assignment->status === LifecycleStatus::Provisioning
            || $assignment->status === LifecycleStatus::Failed
            && in_array(
                needle: $assignment->error_code,
                haystack: ['macos.setup_failed', 'node.unreachable', 'macos.verification_failed'],
                strict: true,
            );
        $requiresLocalSetup = $assignment->role === RoleName::AppDev
        && $assignment->node->platform === 'darwin'
        && $setupEligible
        && in_array(
            needle: $assignment->node->failed_step,
            haystack: [null, 'local-setup'],
            strict: true,
        );

        return new self(
            role: $assignment->role->value,
            status: $assignment->status->value,
            failedStep: $assignment->failed_step,
            errorCode: $assignment->error_code,
            localActionRequired: $requiresLocalSetup,
            localCommand: $requiresLocalSetup ? 'orbit node:setup app-dev' : null,
        );
    }
}
