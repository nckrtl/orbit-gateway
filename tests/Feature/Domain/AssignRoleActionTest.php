<?php

declare(strict_types=1);

use App\Actions\Nodes\AssignRoleAction;
use App\Domain\Nodes\RoleAssignmentException;
use App\Domain\Nodes\RoleName;
use App\Models\Node;

describe(AssignRoleAction::class, function (): void {
    it('assigns compatible roles idempotently', function (): void {
        $node = Node::query()->create([
            'name' => 'gateway',
            'public_ssh_host' => '85.9.218.89',
        ]);
        $action = app(AssignRoleAction::class);

        $first = $action->execute($node, RoleName::Gateway);
        $second = $action->execute($node, RoleName::Gateway);
        $vpn = $action->execute($node, RoleName::Vpn);

        expect($first->is($second))
            ->toBeTrue()
            ->and($vpn->role)
            ->toBe(RoleName::Vpn)
            ->and($node->roles()->count())
            ->toBe(2);
    });

    it('rejects a singleton role on a second node', function (): void {
        $first = Node::query()->create([
            'name' => 'gateway-one',
            'public_ssh_host' => '85.9.218.89',
        ]);
        $second = Node::query()->create([
            'name' => 'gateway-two',
            'public_ssh_host' => '85.9.218.90',
        ]);
        $action = app(AssignRoleAction::class);
        $action->execute($first, RoleName::Gateway);

        expect(fn () => $action->execute($second, RoleName::Gateway))
            ->toThrow(RoleAssignmentException::class, 'Role [gateway] is already assigned to node [gateway-one].');
    });

    it('rejects conflicting application roles on one node', function (): void {
        $node = Node::query()->create([
            'name' => 'applications',
            'public_ssh_host' => '94.237.40.75',
        ]);
        $action = app(AssignRoleAction::class);
        $action->execute($node, RoleName::AppDev);

        expect(fn () => $action->execute($node, RoleName::AppProd))
            ->toThrow(RoleAssignmentException::class, 'Role [app-prod] conflicts with assigned role [app-dev].');
    });
});
