<?php

declare(strict_types=1);

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * @property int $id
 * @property string $name
 * @property string $slug
 * @property string $repository_url
 * @property array<string, mixed>|null $defaults
 */
final class App extends Model
{
    /** @var array<int, string> */
    #[\Override]
    protected $fillable = ['name', 'slug', 'repository_url', 'defaults'];

    /** @var array<array-key, string> */
    #[\Override]
    protected $hidden = ['defaults'];

    /** @return HasMany<Instance, $this> */
    public function instances(): HasMany
    {
        return $this->hasMany(Instance::class);
    }

    /** @return array<string, string> */
    protected function casts(): array
    {
        return ['defaults' => 'array'];
    }
}
