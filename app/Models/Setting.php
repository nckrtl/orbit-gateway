<?php

declare(strict_types=1);

namespace App\Models;

use App\Domain\Settings\SettingScopeType;
use Illuminate\Database\Eloquent\Model;

/**
 * @property int $id
 * @property SettingScopeType $scope_type
 * @property int $scope_id
 * @property string $key
 * @property string|null $value
 * @property bool $is_secret
 */
final class Setting extends Model
{
    /** @var array<int, string> */
    #[\Override]
    protected $fillable = ['scope_type', 'scope_id', 'key', 'value', 'is_secret'];

    /**
     * @mago-expect lint:no-literal-password The cast name is not a credential.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'scope_type' => SettingScopeType::class,
            'scope_id' => 'integer',
            'is_secret' => 'boolean',
        ];
    }
}
