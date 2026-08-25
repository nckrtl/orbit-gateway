<?php

declare(strict_types=1);

namespace App\Models;

use App\Domain\Processes\DesiredProcessState;
use App\Domain\Processes\ProcessRuntime;
use App\Domain\Shared\LifecycleStatus;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;

/**
 * @property int $id
 * @property string $name
 * @property ProcessRuntime $runtime
 * @property string $working_directory
 * @property array<string, mixed> $runtime_config
 * @property DesiredProcessState $desired_state
 * @property LifecycleStatus $status
 * @property-read Instance|Workspace $owner
 */
final class Process extends Model
{
    /** @var array<int, string> */
    protected $fillable = [
        'owner_type',
        'owner_id',
        'name',
        'runtime',
        'working_directory',
        'runtime_config',
        'restart_policy',
        'desired_state',
        'status',
        'failed_step',
        'error_code',
    ];

    /** @return MorphTo<Model, $this> */
    public function owner(): MorphTo
    {
        return $this->morphTo();
    }

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'runtime' => ProcessRuntime::class,
            'runtime_config' => 'array',
            'desired_state' => DesiredProcessState::class,
            'status' => LifecycleStatus::class,
        ];
    }
}
