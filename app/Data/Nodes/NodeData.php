<?php

declare(strict_types=1);

namespace App\Data\Nodes;

use App\Domain\Nodes\RoleName;
use App\Models\Node;
use Spatie\LaravelData\Data;

/** @mago-expect lint:excessive-parameter-list */
final class NodeData extends Data
{
    /** @param list<string> $roles */
    public function __construct(
        public int $id,
        public string $name,
        public string $status,
        public string $publicSshHost,
        public int $publicSshPort,
        public string $sshUser,
        public ?string $wireguardAddress,
        public array $roles,
    ) {}

    public static function fromModel(Node $node): self
    {
        return new self(
            id: $node->id,
            name: $node->name,
            status: $node->status->value,
            publicSshHost: $node->public_ssh_host,
            publicSshPort: $node->public_ssh_port,
            sshUser: $node->ssh_user,
            wireguardAddress: $node->wireguard_address,
            roles: array_values(
                $node
                    ->roles
                    ->pluck('role')
                    ->map(
                        static fn (RoleName $role): string => $role->value,
                    )
                    ->all(),
            ),
        );
    }
}
