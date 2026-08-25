<?php

declare(strict_types=1);

use App\Domain\Nodes\RoleName;
use App\Domain\Nodes\RoleRegistry;

describe(RoleRegistry::class, function (): void {
    it('defines the four version-one roles and their placement rules', function (): void {
        $registry = new RoleRegistry;

        expect($registry->names())
            ->toBe([
                RoleName::Gateway,
                RoleName::Vpn,
                RoleName::AppDev,
                RoleName::AppProd,
            ])
            ->and($registry->definition(RoleName::Gateway)->singleton)
            ->toBeTrue()
            ->and($registry->definition(RoleName::Vpn)->singleton)
            ->toBeTrue()
            ->and($registry->definition(RoleName::AppDev)->singleton)
            ->toBeFalse()
            ->and($registry->definition(RoleName::AppProd)->singleton)
            ->toBeFalse();
    });

    it('keeps gateway and application ownership models apart', function (): void {
        $registry = new RoleRegistry;

        expect($registry->conflicts(RoleName::Gateway, RoleName::AppDev))
            ->toBeTrue()
            ->and($registry->conflicts(RoleName::Gateway, RoleName::AppProd))
            ->toBeTrue()
            ->and($registry->conflicts(RoleName::AppDev, RoleName::AppProd))
            ->toBeTrue()
            ->and($registry->conflicts(RoleName::Gateway, RoleName::Vpn))
            ->toBeFalse();
    });
});
