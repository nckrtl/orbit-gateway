<?php

declare(strict_types=1);

namespace App\Infrastructure\Nodes\Roles;

use App\Domain\Nodes\RoleBaseline;
use App\Domain\Nodes\RoleBaselineConverger;
use App\Domain\Nodes\RoleName;
use App\Models\Node;
use App\Models\NodeRole;

final readonly class NativeRoleBaselineConverger implements RoleBaselineConverger
{
    public function __construct(
        private GatewayRoleBaseline $gateway,
        private VpnRoleBaseline $vpn,
        private AppDevRoleBaseline $appDev,
        private AppProdRoleBaseline $appProd,
    ) {}

    public function converge(Node $node, NodeRole $assignment): void
    {
        $this->baseline($assignment->role)->converge($node, $assignment);
    }

    public function remove(Node $node, NodeRole $assignment, bool $purgeData): void
    {
        $this->baseline($assignment->role)->remove($node, $assignment, $purgeData);
    }

    private function baseline(RoleName $role): RoleBaseline
    {
        return match ($role) {
            RoleName::Gateway => $this->gateway,
            RoleName::Vpn => $this->vpn,
            RoleName::AppDev => $this->appDev,
            RoleName::AppProd => $this->appProd,
        };
    }
}
