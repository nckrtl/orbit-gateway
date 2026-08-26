<?php

declare(strict_types=1);

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * @property int $id
 * @property int $consumer_node_id
 * @property int $serving_node_id
 * @property-read Node $consumer
 * @property-read Node $serving
 */
final class NodeAccess extends Model
{
    /** @var string|null */
    #[\Override]
    protected $table = 'node_access';

    /** @var array<int, string> */
    #[\Override]
    protected $fillable = [
        'consumer_node_id',
        'serving_node_id',
    ];

    /** @return BelongsTo<Node, $this> */
    public function consumer(): BelongsTo
    {
        return $this->belongsTo(Node::class, 'consumer_node_id');
    }

    /** @return BelongsTo<Node, $this> */
    public function serving(): BelongsTo
    {
        return $this->belongsTo(Node::class, 'serving_node_id');
    }
}
