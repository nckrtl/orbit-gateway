<?php

declare(strict_types=1);

namespace App\Models;

use App\Domain\Shared\LifecycleStatus;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * @property int $id
 * @property string $name
 * @property LifecycleStatus $status
 * @property string $platform
 * @property string|null $architecture
 * @property string $public_ssh_host
 * @property int $public_ssh_port
 * @property string $ssh_user
 * @property string|null $tld
 * @property string|null $wireguard_address
 * @property string|null $wireguard_public_key
 * @property string|null $wireguard_endpoint_override
 * @property string|null $dns_server_override
 * @property string|null $ssh_host_fingerprint
 * @property-read \Illuminate\Database\Eloquent\Collection<int, NodeRole> $roles
 * @property-read \Illuminate\Database\Eloquent\Collection<int, Node> $accessibleNodes
 * @property-read \Illuminate\Database\Eloquent\Collection<int, Node> $accessingNodes
 */
final class Node extends Model
{
    /** @var array<string, mixed> */
    #[\Override]
    protected $attributes = [
        'public_ssh_port' => 22,
    ];

    /** @var array<int, string> */
    #[\Override]
    protected $fillable = [
        'name',
        'status',
        'platform',
        'architecture',
        'tld',
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

    /** @return BelongsToMany<Node, $this> */
    public function accessibleNodes(): BelongsToMany
    {
        return $this->belongsToMany(
            self::class,
            'node_access',
            'consumer_node_id',
            'serving_node_id',
        )->withTimestamps();
    }

    /** @return BelongsToMany<Node, $this> */
    public function accessingNodes(): BelongsToMany
    {
        return $this->belongsToMany(
            self::class,
            'node_access',
            'serving_node_id',
            'consumer_node_id',
        )->withTimestamps();
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
