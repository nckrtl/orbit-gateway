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
 * @property-read Node $node
 */
final class NodeRole extends Model
{
    /** @var array<int, string> */
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

    /** @return array<string, class-string|literal-string> */
    protected function casts(): array
    {
        return [
            'role' => RoleName::class,
            'status' => LifecycleStatus::class,
        ];
    }
}
