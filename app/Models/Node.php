<?php

declare(strict_types=1);

namespace App\Models;

use App\Domain\Shared\LifecycleStatus;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * @property int $id
 * @property string $name
 * @property LifecycleStatus $status
 * @property string $public_ssh_host
 * @property string|null $wireguard_address
 */
final class Node extends Model
{
    /** @var array<int, string> */
    protected $fillable = [
        'name',
        'status',
        'platform',
        'architecture',
        'public_ssh_host',
        'public_ssh_port',
        'ssh_user',
        'wireguard_address',
        'wireguard_public_key',
        'wireguard_endpoint_override',
        'dns_server_override',
        'ssh_host_key_type',
        'ssh_host_key',
        'ssh_host_fingerprint',
        'failed_step',
        'error_code',
    ];

    /** @return HasMany<NodeRole, $this> */
    public function roles(): HasMany
    {
        return $this->hasMany(NodeRole::class);
    }

    /** @return HasMany<Instance, $this> */
    public function instances(): HasMany
    {
        return $this->hasMany(Instance::class);
    }

    /** @return HasMany<FirewallRule, $this> */
    public function firewallRules(): HasMany
    {
        return $this->hasMany(FirewallRule::class);
    }

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'status' => LifecycleStatus::class,
            'public_ssh_port' => 'integer',
        ];
    }
}
