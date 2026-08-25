<?php

declare(strict_types=1);

namespace App\Data\Nodes;

use App\Domain\Nodes\RoleName;
use App\Models\Node;
use Illuminate\Support\Collection;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\SnakeCaseMapper;

/** @mago-expect lint:excessive-parameter-list */
#[MapOutputName(SnakeCaseMapper::class)]
final class NodeData extends Data
{
    /** @param list<string> $roles */
    public function __construct(
        public int $id,
        public string $name,
        public string $status,
        public ?string $platform,
        public ?string $architecture,
        public string $publicSshHost,
        public int $publicSshPort,
        public string $sshUser,
        public ?string $wireguardAddress,
        public ?string $sshHostFingerprint,
        public ?string $failedStep,
        public ?string $errorCode,
        public array $roles,
    ) {}

    public static function fromModel(Node $node): self
    {
        /** @var ?string $platform */
        $platform = $node->getAttribute('platform');
        /** @var ?string $architecture */
        $architecture = $node->getAttribute('architecture');
        /** @var ?string $sshHostFingerprint */
        $sshHostFingerprint = $node->getAttribute('ssh_host_fingerprint');
        /** @var ?string $failedStep */
        $failedStep = $node->getAttribute('failed_step');
        /** @var ?string $errorCode */
        $errorCode = $node->getAttribute('error_code');

        return new self(
            id: $node->id,
            name: $node->name,
            status: $node->status->value,
            platform: $platform,
            architecture: $architecture,
            publicSshHost: $node->public_ssh_host,
            publicSshPort: $node->public_ssh_port,
            sshUser: $node->ssh_user,
            wireguardAddress: $node->wireguard_address,
            sshHostFingerprint: $sshHostFingerprint,
            failedStep: $failedStep,
            errorCode: $errorCode,
            roles: self::roles($node),
        );
    }

    /** @return list<string> */
    private static function roles(Node $node): array
    {
        /** @var array<string, int> $roleOrder */
        $roleOrder = collect(RoleName::cases())
            ->map(static fn (RoleName $role): string => $role->value)
            ->values()
            ->flip()
            ->map(static fn (int $index): int => $index)
            ->all();

        /** @var Collection<int, RoleName> $roles */
        $roles = $node->roles->pluck('role');

        /** @mago-expect lint:inline-variable-return Static analysis needs the explicit typed local to preserve list<string>. */
        /** @var list<string> $sortedRoles */
        $sortedRoles = $roles
            ->sortBy(
                static fn (RoleName $role): int => $roleOrder[$role->value] ?? PHP_INT_MAX,
            )
            ->map(static fn (RoleName $role): string => $role->value)
            ->values()
            ->all();

        return $sortedRoles;
    }
}
