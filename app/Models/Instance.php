<?php

declare(strict_types=1);

namespace App\Models;

use App\Domain\Instances\CertificateMode;
use App\Domain\Shared\LifecycleStatus;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\MorphMany;

/**
 * @property int $id
 * @property int $app_id
 * @property int $node_id
 * @property string $name
 * @property string $checkout_path
 * @property string $php_version
 * @property CertificateMode $certificate_mode
 * @property LifecycleStatus $status
 * @property-read App $app
 * @property-read Node $node
 */
final class Instance extends Model
{
    /** @var array<int, string> */
    protected $fillable = [
        'app_id',
        'node_id',
        'name',
        'environment',
        'checkout_path',
        'document_root',
        'php_version',
        'hostname',
        'certificate_mode',
        'status',
        'failed_step',
        'error_code',
    ];

    /** @return BelongsTo<App, $this> */
    public function app(): BelongsTo
    {
        return $this->belongsTo(App::class);
    }

    /** @return BelongsTo<Node, $this> */
    public function node(): BelongsTo
    {
        return $this->belongsTo(Node::class);
    }

    /** @return HasMany<Workspace, $this> */
    public function workspaces(): HasMany
    {
        return $this->hasMany(Workspace::class);
    }

    /** @return MorphMany<Process, $this> */
    public function processes(): MorphMany
    {
        return $this->morphMany(Process::class, 'owner');
    }

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'certificate_mode' => CertificateMode::class,
            'status' => LifecycleStatus::class,
        ];
    }
}
