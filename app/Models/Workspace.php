<?php

declare(strict_types=1);

namespace App\Models;

use App\Domain\Shared\LifecycleStatus;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\MorphMany;

/**
 * @property int $id
 * @property int $instance_id
 * @property string $name
 * @property string $branch
 * @property string $checkout_path
 * @property string|null $php_version
 * @property string $hostname
 * @property LifecycleStatus $status
 * @property string|null $failed_step
 * @property string|null $error_code
 * @property-read Instance $instance
 */
final class Workspace extends Model
{
    /** @var array<string, mixed> */
    protected $attributes = ['status' => 'provisioning'];

    /** @var array<int, string> */
    protected $fillable = [
        'instance_id',
        'name',
        'branch',
        'checkout_path',
        'php_version',
        'hostname',
        'status',
        'failed_step',
        'error_code',
    ];

    /** @return BelongsTo<Instance, $this> */
    public function instance(): BelongsTo
    {
        return $this->belongsTo(Instance::class);
    }

    /** @return MorphMany<Process, $this> */
    public function processes(): MorphMany
    {
        return $this->morphMany(Process::class, 'owner');
    }

    /** @return array<string, string> */
    protected function casts(): array
    {
        return ['status' => LifecycleStatus::class];
    }
}
