<?php

declare(strict_types=1);

namespace App\Domain\AppDev;

use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Domain\Shared\ResourceOperationException;
use App\Models\Node;

/** @mago-expect lint:cyclomatic-complexity This boundary rejects each unsafe platform and path shape explicitly. */
final readonly class AppDevHostPaths
{
    public function home(Node $node, RoleName $role): string
    {
        $this->assertSupported($node, $role);

        if ($node->platform === 'linux') {
            return '/home/orbit';
        }

        $this->assertDarwinUser($node->ssh_user);

        return "/Users/{$node->ssh_user}";
    }

    public function instanceCheckout(Node $node, RoleName $role, string $app, string $instance): string
    {
        $this->assertSegment($app, 'instance.path_invalid');
        $this->assertSegment($instance, 'instance.path_invalid');
        $this->assertSupported($node, $role);

        if ($role === RoleName::AppProd) {
            return "/var/www/{$app}/{$instance}";
        }

        return $this->home($node, $role)."/apps/{$app}";
    }

    public function workspaceCheckout(Node $node, string $app, string $workspace): string
    {
        $this->assertSegment($app, 'workspace.path_invalid');
        $this->assertSegment($workspace, 'workspace.path_invalid');
        $home = $this->home($node, RoleName::AppDev);

        return "{$home}/.orbit/worktrees/{$app}/{$workspace}";
    }

    public function resolveWorkspaceCheckout(
        Node $node,
        string $app,
        string $workspace,
        ?string $override,
    ): string {
        $managed = $this->workspaceCheckout($node, $app, $workspace);

        if ($override === null || $override === $managed) {
            return $managed;
        }

        if ($node->platform === 'darwin') {
            throw new ResourceOperationException(
                errorCode: 'workspace.path_unsupported',
                message: 'Darwin workspaces must use the managed Orbit worktree path.',
            );
        }

        if ($this->isSafeLinuxWorkspaceOverride($override)) {
            return $override;
        }

        throw new ResourceOperationException(
            errorCode: 'workspace.path_unsupported',
            message: 'The workspace checkout path is not supported.',
        );
    }

    private function assertSupported(Node $node, RoleName $role): void
    {
        $supported =
            $node->platform === 'linux'
            && in_array(needle: $role, haystack: [RoleName::AppDev, RoleName::AppProd], strict: true)
            || $node->platform === 'darwin' && $role === RoleName::AppDev;

        if ($supported) {
            $roles = match (true) {
                $node->relationLoaded('roles') => $node->roles,
                $node->exists => $node->roles()->get(),
                default => collect(),
            };
            $hasActiveRole = $roles->contains(
                static fn (\App\Models\NodeRole $nodeRole): bool => (
                    $nodeRole->role === $role
                    && $nodeRole->status === LifecycleStatus::Active
                ),
            );

            if ($hasActiveRole) {
                return;
            }

            throw new ResourceOperationException(
                errorCode: 'instance.node_not_app_host',
                message: "The node does not have an active [{$role->value}] role.",
            );
        }

        throw new ResourceOperationException(
            errorCode: 'instance.platform_unsupported',
            message: "Platform [{$node->platform}] does not support the requested application role.",
        );
    }

    private function assertDarwinUser(string $user): void
    {
        if (
            preg_match('/\A[a-z_][a-z0-9_-]{0,63}\z/D', $user) === 1
            && ! in_array(needle: $user, haystack: ['root', 'orbit'], strict: true)
        ) {
            return;
        }

        throw new ResourceOperationException(
            errorCode: 'node.ssh_user_invalid',
            message: 'Darwin application hosting requires a canonical personal SSH user.',
        );
    }

    private function assertSegment(string $segment, string $errorCode): void
    {
        if (
            preg_match('/\A[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?\z/D', $segment) === 1
            && ! in_array(needle: $segment, haystack: ['.', '..'], strict: true)
        ) {
            return;
        }

        throw new ResourceOperationException(
            errorCode: $errorCode,
            message: 'The managed application path contains an invalid segment.',
        );
    }

    private function isSafeLinuxWorkspaceOverride(string $path): bool
    {
        if (! str_starts_with($path, '/home/orbit/')) {
            return false;
        }

        if (preg_match('#\A/home/orbit/(?:apps(?:/|\z)|\.(?!orbit/worktrees/))#', $path) === 1) {
            return false;
        }

        $segments = explode('/', mb_substr($path, mb_strlen('/home/orbit/')));

        return array_all(
            $segments,
            static fn (string $segment): bool => ! (
                $segment === ''
                || $segment === '.'
                || $segment === '..'
                || preg_match('/\A[A-Za-z0-9._-]+\z/D', $segment) !== 1
            ),
        );
    }
}
