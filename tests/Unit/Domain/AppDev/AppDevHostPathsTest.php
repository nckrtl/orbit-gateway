<?php

declare(strict_types=1);

use App\Domain\AppDev\AppDevHostPaths;
use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Domain\Shared\ResourceOperationException;
use App\Models\Node;
use App\Models\NodeRole;
use Illuminate\Database\Eloquent\Collection;

/**
 * @mago-expect lint:halstead The suite asserts the complete cross-platform path boundary.
 */
describe('app-dev host paths', function (): void {
    it('derives the exact managed paths for Linux and Darwin app-dev hosts', function (): void {
        $paths = new AppDevHostPaths;
        $linux = host_paths_node(platform: 'linux', user: 'orbit', roles: [RoleName::AppDev, RoleName::AppProd]);
        $darwin = host_paths_node(platform: 'darwin', user: 'nckrtl', roles: [RoleName::AppDev]);

        expect($paths->home($linux, RoleName::AppDev))
            ->toBe('/home/orbit')
            ->and($paths->instanceCheckout($linux, RoleName::AppDev, 'acme', 'dev'))
            ->toBe('/home/orbit/apps/acme')
            ->and($paths->workspaceCheckout($linux, 'acme', 'feature-one'))
            ->toBe('/home/orbit/.orbit/worktrees/acme/feature-one')
            ->and($paths->home($darwin, RoleName::AppDev))
            ->toBe('/Users/nckrtl')
            ->and($paths->instanceCheckout($darwin, RoleName::AppDev, 'acme', 'dev'))
            ->toBe('/Users/nckrtl/apps/acme')
            ->and($paths->workspaceCheckout($darwin, 'acme', 'feature-one'))
            ->toBe('/Users/nckrtl/.orbit/worktrees/acme/feature-one')
            ->and($paths->instanceCheckout($linux, RoleName::AppProd, 'acme', 'blue'))
            ->toBe('/var/www/acme/blue');
    });

    it('rejects unsafe Darwin users and unsafe managed path segments', function (string $user, string $segment): void {
        $paths = new AppDevHostPaths;
        $node = host_paths_node(platform: 'darwin', user: $user, roles: [RoleName::AppDev]);
        $exception = null;

        try {
            $paths->instanceCheckout($node, RoleName::AppDev, $segment, 'dev');
        } catch (ResourceOperationException $caught) {
            $exception = $caught;
        }

        expect($exception)
            ->toBeInstanceOf(ResourceOperationException::class)
            ->and($exception?->errorCode)
            ->toBe($user === 'nckrtl' ? 'instance.path_invalid' : 'node.ssh_user_invalid');
    })->with([
        'root user' => ['root', 'acme'],
        'orbit alias user' => ['orbit', 'acme'],
        'empty user' => ['', 'acme'],
        'non-canonical user' => ['Nick', 'acme'],
        'user separator' => ['nick/name', 'acme'],
        'user traversal' => ['..', 'acme'],
        'user control byte' => ["nick\nname", 'acme'],
        'empty segment' => ['nckrtl', ''],
        'root alias segment' => ['nckrtl', '.'],
        'parent alias segment' => ['nckrtl', '..'],
        'segment separator' => ['nckrtl', 'acme/site'],
        'segment control byte' => ['nckrtl', "acme\nsite"],
    ]);

    it('rejects Darwin app-prod and unsupported platforms', function (string $platform, RoleName $role): void {
        $paths = new AppDevHostPaths;
        $node = host_paths_node(platform: $platform, user: 'nckrtl', roles: [$role]);
        $exception = null;

        try {
            $paths->instanceCheckout($node, $role, 'acme', 'blue');
        } catch (ResourceOperationException $caught) {
            $exception = $caught;
        }

        expect($exception)
            ->toBeInstanceOf(ResourceOperationException::class)
            ->and($exception?->errorCode)
            ->toBe('instance.platform_unsupported');
    })->with([
        'Darwin production' => ['darwin', RoleName::AppProd],
        'unsupported platform' => ['windows', RoleName::AppDev],
    ]);

    it('keeps the Linux custom workspace contract and restricts Darwin to its exact managed root', function (): void {
        $paths = new AppDevHostPaths;
        $linux = host_paths_node(platform: 'linux', user: 'orbit', roles: [RoleName::AppDev]);
        $darwin = host_paths_node(platform: 'darwin', user: 'nckrtl', roles: [RoleName::AppDev]);

        expect($paths->resolveWorkspaceCheckout(
            node: $linux,
            app: 'acme',
            workspace: 'feature-one',
            override: '/home/orbit/custom-worktrees/acme-feature-one',
        ))
            ->toBe('/home/orbit/custom-worktrees/acme-feature-one')
            ->and($paths->resolveWorkspaceCheckout(
                node: $darwin,
                app: 'acme',
                workspace: 'feature-one',
                override: '/Users/nckrtl/.orbit/worktrees/acme/feature-one',
            ))
            ->toBe('/Users/nckrtl/.orbit/worktrees/acme/feature-one');

        expect(fn (): string => $paths->resolveWorkspaceCheckout(
            node: $darwin,
            app: 'acme',
            workspace: 'feature-one',
            override: '/Users/nckrtl/custom-worktrees/acme-feature-one',
        ))
            ->toThrow(ResourceOperationException::class, 'Darwin workspaces must use the managed Orbit worktree path.');
    });

    it('rejects a missing or inactive matching role for every supported platform role pair', function (
        string $platform,
        RoleName $requested,
        array $roles,
    ): void {
        $node = host_paths_node(
            platform: $platform,
            user: $platform === 'darwin' ? 'nckrtl' : 'orbit',
            roles: $roles,
        );

        expect(fn (): string => new AppDevHostPaths()->home($node, $requested))
            ->toThrow(ResourceOperationException::class);
    })->with([
        'Linux app-dev missing' => ['linux', RoleName::AppDev, []],
        'Linux app-dev has only app-prod' => ['linux', RoleName::AppDev, [RoleName::AppProd]],
        'Linux app-prod has only app-dev' => ['linux', RoleName::AppProd, [RoleName::AppDev]],
        'Darwin app-dev missing' => ['darwin', RoleName::AppDev, []],
    ]);

    it('rejects a matching role that is not active', function (): void {
        $node = host_paths_node(platform: 'darwin', user: 'nckrtl', roles: [RoleName::AppDev]);
        $node->roles->firstOrFail()->status = LifecycleStatus::Failed;

        expect(fn (): string => new AppDevHostPaths()->home($node, RoleName::AppDev))
            ->toThrow(ResourceOperationException::class);
    });
});

/** @param list<RoleName> $roles */
function host_paths_node(string $platform, string $user, array $roles): Node
{
    $node = new Node(['platform' => $platform, 'ssh_user' => $user]);
    $node->setRelation(
        'roles',
        new Collection(array_map(
            static fn (RoleName $role): NodeRole => new NodeRole([
                'role' => $role,
                'status' => LifecycleStatus::Active,
            ]),
            $roles,
        )),
    );

    return $node;
}
