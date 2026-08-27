<?php

declare(strict_types=1);

namespace App\Models;

use App\Domain\Shared\LifecycleStatus;
use App\Domain\Tools\ToolManagerName;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * @property int $id
 * @property int $node_id
 * @property ToolManagerName $name
 * @property LifecycleStatus $status
 * @property string|null $installed_version
 * @property string|null $failed_step
 * @property string|null $error_code
 * @property-read Node $node
 * @property-read \Illuminate\Database\Eloquent\Collection<int, Tool> $tools
 */
final class ToolManagerRecord extends Model
{
    /** @var string|null */
    #[\Override]
    protected $table = 'tool_managers';

    /** @var array<int, string> */
    #[\Override]
    protected $fillable = [
        'node_id',
        'name',
        'status',
        'installed_version',
        'failed_step',
        'error_code',
    ];

    /** @return BelongsTo<Node, $this> */
    public function node(): BelongsTo
    {
        return $this->belongsTo(Node::class);
    }

    /** @return HasMany<Tool, $this> */
    public function tools(): HasMany
    {
        return $this->hasMany(Tool::class, 'tool_manager_id');
    }

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'name' => ToolManagerName::class,
            'status' => LifecycleStatus::class,
        ];
    }
}
