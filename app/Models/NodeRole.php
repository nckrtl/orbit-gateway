<?php

declare(strict_types=1);

namespace App\Models;

use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * @property int $id
 * @property int $node_id
 * @property RoleName $role
 * @property LifecycleStatus $status
 * @property string|null $failed_step
 * @property string|null $error_code
 * @property-read Node $node
 */
final class NodeRole extends Model
{
    /** @var array<int, string> */
    #[\Override]
    protected $fillable = [
        'node_id',
        'role',
        'status',
        'failed_step',
        'error_code',
    ];

    /** @return BelongsTo<Node, $this> */
    public function node(): BelongsTo
    {
        return $this->belongsTo(Node::class);
    }

    public function canClaimConvergence(): bool
    {
        if ($this->status === LifecycleStatus::Active) {
            return true;
        }

        return (
            $this->status === LifecycleStatus::Failed
            && is_string($this->failed_step)
            && str_starts_with($this->failed_step, 'converge:')
        );
    }

    public function claimConvergence(): void
    {
        $this->update([
            'status' => LifecycleStatus::Provisioning,
            'failed_step' => null,
            'error_code' => null,
        ]);
    }

    public function markConvergenceActive(): void
    {
        $this->update([
            'status' => LifecycleStatus::Active,
            'failed_step' => null,
            'error_code' => null,
        ]);
    }

    public function markConvergenceFailed(string $step, string $errorCode): void
    {
        $this->update([
            'status' => LifecycleStatus::Failed,
            'failed_step' => "converge:{$step}",
            'error_code' => $errorCode,
        ]);
    }

    /** @return array<string, class-string|literal-string> */
    protected function casts(): array
    {
        return [
            'role' => RoleName::class,
            'status' => LifecycleStatus::class,
        ];
    }
}
