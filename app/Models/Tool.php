<?php

declare(strict_types=1);

namespace App\Models;

use App\Domain\Tools\ToolOperation;
use App\Domain\Tools\ToolStatus;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * @property int $id
 * @property int $node_id
 * @property int $tool_manager_id
 * @property string $package
 * @property string|null $version_constraint
 * @property bool $protected
 * @property ToolStatus $status
 * @property string|null $installed_version
 * @property ToolOperation|null $failed_operation
 * @property string|null $error_code
 * @property-read Node $node
 * @property-read ToolManagerRecord $manager
 */
final class Tool extends Model
{
    /** @var array<string, mixed> */
    #[\Override]
    protected $attributes = [
        'protected' => false,
    ];

    /** @var array<int, string> */
    #[\Override]
    protected $fillable = [
        'node_id',
        'tool_manager_id',
        'package',
        'version_constraint',
        'protected',
        'status',
        'installed_version',
        'failed_operation',
        'error_code',
    ];

    /** @return BelongsTo<Node, $this> */
    public function node(): BelongsTo
    {
        return $this->belongsTo(Node::class);
    }

    /** @return BelongsTo<ToolManagerRecord, $this> */
    public function manager(): BelongsTo
    {
        return $this->belongsTo(ToolManagerRecord::class, 'tool_manager_id');
    }

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'protected' => 'boolean',
            'status' => ToolStatus::class,
            'failed_operation' => ToolOperation::class,
        ];
    }
}
