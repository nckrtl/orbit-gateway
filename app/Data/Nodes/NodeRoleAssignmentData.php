<?php

declare(strict_types=1);

namespace App\Data\Nodes;

use App\Models\NodeRole;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\SnakeCaseMapper;

#[MapOutputName(SnakeCaseMapper::class)]
final class NodeRoleAssignmentData extends Data
{
    public function __construct(
        public int $id,
        public string $role,
        public string $status,
        public ?string $failedStep,
        public ?string $errorCode,
    ) {}

    public static function fromModel(NodeRole $assignment): self
    {
        return new self(
            id: $assignment->id,
            role: $assignment->role->value,
            status: $assignment->status->value,
            failedStep: $assignment->failed_step,
            errorCode: $assignment->error_code,
        );
    }
}
