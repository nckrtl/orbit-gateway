<?php

declare(strict_types=1);

use App\Actions\Nodes\AssignRoleAction;
use App\Domain\Nodes\RoleAssignmentException;
use App\Domain\Nodes\RoleName;
use App\Models\Node;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;

/** @mago-expect lint:halstead The claim matrix keeps each policy and serialization boundary visible. */
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

    it('serializes singleton claims on different nodes before policy validation', function (): void {
        $first = Node::query()->create([
            'name' => 'serialized-gateway-one',
            'public_ssh_host' => '192.0.2.72',
        ]);
        $second = Node::query()->create([
            'name' => 'serialized-gateway-two',
            'public_ssh_host' => '192.0.2.73',
        ]);
        $events = [];
        DB::listen(static function (QueryExecuted $query) use (&$events): void {
            $event = role_claim_query_event($query);

            if ($event !== null) {
                $events[] = $event;
            }
        });
        $action = app(AssignRoleAction::class);

        $action->execute($first, RoleName::Gateway);
        $firstClaim = $events;
        $events = [];

        expect(fn () => $action->execute($second, RoleName::Gateway))
            ->toThrow(
                RoleAssignmentException::class,
                'Role [gateway] is already assigned to node [serialized-gateway-one].',
            );

        expect($firstClaim[0] ?? null)
            ->toBe(['claim-lock', null])
            ->and($events[0] ?? null)
            ->toBe(['claim-lock', null])
            ->and(array_column($firstClaim, 0))
            ->toContain('role-policy')
            ->and(array_column($events, 0))
            ->toContain('role-policy');
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

    it('serializes conflicting claims on one node before policy validation', function (): void {
        $node = Node::query()->create([
            'name' => 'serialized-applications',
            'public_ssh_host' => '192.0.2.74',
        ]);
        $events = [];
        DB::listen(static function (QueryExecuted $query) use (&$events): void {
            $event = role_claim_query_event($query);

            if ($event !== null) {
                $events[] = $event;
            }
        });
        $action = app(AssignRoleAction::class);
        $action->execute($node, RoleName::AppDev);
        $events = [];

        expect(fn () => $action->execute($node, RoleName::AppProd))
            ->toThrow(
                RoleAssignmentException::class,
                'Role [app-prod] conflicts with assigned role [app-dev].',
            );

        expect($events[0] ?? null)
            ->toBe(['claim-lock', null])
            ->and(array_column($events, 0))
            ->toContain('role-policy');
    });

    it('preflights prospective role conflicts without writing assignments', function (): void {
        $node = Node::query()->make(['name' => 'prospective']);
        $action = app(AssignRoleAction::class);

        expect(fn () => $action->preflight(
            $node,
            RoleName::AppDev,
            prospectiveRoles: [RoleName::AppDev, RoleName::AppProd],
        ))
            ->toThrow(RoleAssignmentException::class, 'Role [app-dev] conflicts with requested role [app-prod].');

        expect(Node::query()->where('name', 'prospective')->exists())->toBeFalse();
    });

    it('repeats conflict validation inside the assignment transaction', function (): void {
        $node = Node::query()->create([
            'name' => 'race-safe',
            'public_ssh_host' => '192.0.2.70',
        ]);
        $action = app(AssignRoleAction::class);
        $action->preflight($node, RoleName::AppDev);
        $node->roles()->create(['role' => RoleName::AppProd]);

        expect(fn () => $action->execute($node, RoleName::AppDev))
            ->toThrow(RoleAssignmentException::class, 'Role [app-dev] conflicts with assigned role [app-prod].');

        expect($node->roles()->where('role', RoleName::AppDev->value)->exists())->toBeFalse();
    });

    it('returns one assignment when duplicate claims race through the unique boundary', function (): void {
        $node = Node::query()->create([
            'name' => 'duplicate-safe',
            'public_ssh_host' => '192.0.2.71',
        ]);
        $action = app(AssignRoleAction::class);

        $first = $action->execute($node, RoleName::AppDev);
        $second = $action->execute($node, RoleName::AppDev);

        expect($first->is($second))
            ->toBeTrue()
            ->and($node->roles()->where('role', RoleName::AppDev->value)->count())
            ->toBe(1);
    });
});

/** @return array{0: 'claim-lock'|'claim-source-read'|'role-policy', 1: int|null}|null */
function role_claim_query_event(QueryExecuted $query): ?array
{
    $sql = strtolower($query->sql);

    if (
        str_starts_with($sql, 'update')
        && str_contains($sql, 'nodes')
        && str_contains($sql, 'set "id" = id')
        && str_contains($sql, 'select min(id)')
    ) {
        $nodeId = $query->bindings[0] ?? null;

        return ['claim-lock', is_int($nodeId) ? $nodeId : null];
    }

    if (str_starts_with($sql, 'select') && str_contains($sql, 'nodes') && ! str_contains($sql, 'node_roles')) {
        return ['claim-source-read', null];
    }

    if (str_starts_with($sql, 'select') && str_contains($sql, 'node_roles')) {
        return ['role-policy', null];
    }

    return null;
}
