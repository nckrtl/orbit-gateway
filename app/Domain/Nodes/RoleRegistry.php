<?php

declare(strict_types=1);

namespace App\Domain\Nodes;

final readonly class RoleRegistry
{
    /** @return list<RoleName> */
    public function names(): array
    {
        return [
            RoleName::Gateway,
            RoleName::Vpn,
            RoleName::AppDev,
            RoleName::AppProd,
        ];
    }

    public function definition(RoleName $role): RoleDefinition
    {
        return match ($role) {
            RoleName::Gateway => new RoleDefinition(
                name: $role,
                singleton: true,
                assignableDuringProvisioning: true,
                mutable: false,
                conflicts: [RoleName::AppDev, RoleName::AppProd],
            ),
            RoleName::Vpn => new RoleDefinition(
                name: $role,
                singleton: true,
                assignableDuringProvisioning: true,
                mutable: false,
            ),
            RoleName::AppDev => new RoleDefinition(
                name: $role,
                singleton: false,
                assignableDuringProvisioning: true,
                mutable: true,
                conflicts: [RoleName::Gateway, RoleName::AppProd],
            ),
            RoleName::AppProd => new RoleDefinition(
                name: $role,
                singleton: false,
                assignableDuringProvisioning: true,
                mutable: true,
                conflicts: [RoleName::Gateway, RoleName::AppDev],
            ),
        };
    }

    public function conflicts(RoleName $first, RoleName $second): bool
    {
        return (
            in_array($second, $this->definition($first)->conflicts, strict: true)
            || in_array($first, $this->definition($second)->conflicts, strict: true)
        );
    }
}
