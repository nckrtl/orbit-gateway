<?php

declare(strict_types=1);

namespace App\Data\Workspaces;

use App\Models\Workspace;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\SnakeCaseMapper;

/** @mago-expect lint:excessive-parameter-list */
#[MapOutputName(SnakeCaseMapper::class)]
final class WorkspaceData extends Data
{
    public function __construct(
        public int $id,
        public int $instanceId,
        public int $nodeId,
        public string $name,
        public string $branch,
        public string $checkoutPath,
        public ?string $phpVersion,
        public string $effectivePhpVersion,
        public string $hostname,
        public string $status,
        public ?string $failedStep,
        public ?string $errorCode,
    ) {}

    public static function fromModel(Workspace $workspace): self
    {
        $workspace->loadMissing('instance');
        /** @var ?string $failedStep */
        $failedStep = $workspace->getAttribute('failed_step');
        /** @var ?string $errorCode */
        $errorCode = $workspace->getAttribute('error_code');

        return new self(
            id: $workspace->id,
            instanceId: $workspace->instance_id,
            nodeId: $workspace->instance->node_id,
            name: $workspace->name,
            branch: $workspace->branch,
            checkoutPath: $workspace->checkout_path,
            phpVersion: $workspace->php_version,
            effectivePhpVersion: $workspace->php_version ?? $workspace->instance->php_version,
            hostname: $workspace->hostname,
            status: $workspace->status->value,
            failedStep: $failedStep,
            errorCode: $errorCode,
        );
    }
}
