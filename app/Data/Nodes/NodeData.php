<?php

declare(strict_types=1);

namespace App\Data\Nodes;

use App\Domain\Nodes\RoleName;
use App\Models\Node;
use App\Models\NodeRole;
use Illuminate\Support\Collection;
use Spatie\LaravelData\Attributes\MapOutputName;
use Spatie\LaravelData\Data;
use Spatie\LaravelData\Mappers\SnakeCaseMapper;

/** @mago-expect lint:excessive-parameter-list */
#[MapOutputName(SnakeCaseMapper::class)]
final class NodeData extends Data
{
    /**
     * @param list<string> $roles
     * @param list<array<string, mixed>> $roleAssignments
     */
    public function __construct(
        public int $id,
        public string $name,
        public string $status,
        public ?string $platform,
        public ?string $architecture,
        public ?string $tld,
        public string $publicSshHost,
        public int $publicSshPort,
        public string $sshUser,
        public ?string $wireguardAddress,
        public ?string $wireguardPublicKey,
        public ?string $wireguardEndpointOverride,
        public ?string $dnsServerOverride,
        public ?string $sshHostFingerprint,
        public ?string $failedStep,
        public ?string $errorCode,
        public array $roles,
        public array $roleAssignments,
    ) {}

    public static function fromModel(Node $node): self
    {
        /** @var ?string $platform */
        $platform = $node->getAttribute('platform');
        /** @var ?string $architecture */
        $architecture = $node->getAttribute('architecture');
        /** @var ?string $tld */
        $tld = $node->getAttribute('tld');
        /** @var ?string $wireguardPublicKey */
        $wireguardPublicKey = $node->getAttribute('wireguard_public_key');
        /** @var ?string $wireguardEndpointOverride */
        $wireguardEndpointOverride = $node->getAttribute('wireguard_endpoint_override');
        /** @var ?string $dnsServerOverride */
        $dnsServerOverride = $node->getAttribute('dns_server_override');
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
            tld: $tld,
            publicSshHost: $node->public_ssh_host,
            publicSshPort: $node->public_ssh_port,
            sshUser: $node->ssh_user,
            wireguardAddress: $node->wireguard_address,
            wireguardPublicKey: $wireguardPublicKey,
            wireguardEndpointOverride: $wireguardEndpointOverride,
            dnsServerOverride: $dnsServerOverride,
            sshHostFingerprint: $sshHostFingerprint,
            failedStep: $failedStep,
            errorCode: $errorCode,
            roles: self::roles($node),
            roleAssignments: self::roleAssignments($node),
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

    /** @return list<array<string, mixed>> */
    private static function roleAssignments(Node $node): array
    {
        /** @var array<string, int> $roleOrder */
        $roleOrder = collect(RoleName::cases())
            ->map(static fn (RoleName $role): string => $role->value)
            ->values()
            ->flip()
            ->map(static fn (int $index): int => $index)
            ->all();

        /** @mago-expect lint:inline-variable-return Static analysis needs the explicit typed local to preserve the list shape. */
        $assignments = array_values(
            $node
                ->roles
                ->sortBy(static fn ($assignment): int => $roleOrder[$assignment->role->value] ?? PHP_INT_MAX)
                ->map(self::serializeRoleAssignment(...))
                ->all(),
        );

        return $assignments;
    }

    /**
     * @return array<string, mixed>
     *
     * @mago-expect lint:inline-variable-return Static analysis needs the explicit array-key refinement.
     */
    private static function serializeRoleAssignment(NodeRole $assignment): array
    {
        /** @var array<string, mixed> $serialized */
        $serialized = NodeRoleAssignmentData::fromModel($assignment)->toArray();

        return $serialized;
    }
}
