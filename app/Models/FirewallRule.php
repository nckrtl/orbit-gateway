<?php

declare(strict_types=1);

namespace App\Models;

use App\Domain\Firewall\FirewallAction;
use App\Domain\Shared\LifecycleStatus;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * @property int $id
 * @property int $node_id
 * @property string $name
 * @property FirewallAction $action
 * @property string $source
 * @property string $protocol
 * @property string $port
 * @property LifecycleStatus $status
 * @property string|null $failed_step
 * @property string|null $error_code
 * @property-read Node $node
 */
final class FirewallRule extends Model
{
    /** @var array<int, string> */
    #[\Override]
    protected $fillable = [
        'node_id',
        'name',
        'action',
        'source',
        'protocol',
        'port',
        'status',
        'failed_step',
        'error_code',
    ];

    /** @return BelongsTo<Node, $this> */
    public function node(): BelongsTo
    {
        return $this->belongsTo(Node::class);
    }

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'action' => FirewallAction::class,
            'status' => LifecycleStatus::class,
        ];
    }
}
