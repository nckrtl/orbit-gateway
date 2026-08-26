<?php

declare(strict_types=1);

namespace App\Infrastructure\MacOs;

use App\Domain\AppDev\AppDevHostPaths;
use App\Domain\AppDev\AppDevSourceManager;
use App\Domain\AppDev\AppDevSourceOperationLock;
use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\Shared\ResourceOperationException;
use App\Domain\SourceControl\GitRepositoryOrigin;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshExecutor;
use App\Models\Instance;
use App\Models\Node;
use App\Models\Workspace;

final readonly class MacOsAppDevSourceManager implements AppDevSourceManager
{
    public function __construct(
        private AppDevHostPaths $paths,
        private MacOsSshConnectionFactory $connections,
        private SshExecutor $ssh,
        private MacOsSteadyStateCommandGuard $guard,
        private AppDevSourceOperationLock $lock,
    ) {}

    public function convergeInstance(Instance $instance): void
    {
        $instance->loadMissing(['app', 'node']);
        $repository = GitRepositoryOrigin::validate($instance->app->repository_url);
        $checkout = $this->instanceCheckout($instance);
        $home = $this->paths->home($instance->node, \App\Domain\Nodes\RoleName::AppDev);

        $this->lockedExecute(
            node: $instance->node,
            command: new RemoteCommand(
                arguments: [
                    '/bin/bash',
                    '-seu',
                    '--',
                    $repository,
                    $checkout,
                    $instance->document_root,
                    $home,
                    $this->gitPath($instance->node),
                ],
                input: <<<'BASH'
                    repository=$1
                    checkout=$2
                    document_root=$3
                    home=$4
                    git_path=$5
                    git() { "$git_path" "$@"; }
                    parent=$(dirname "$checkout")
                    test "$parent" = "$home/apps"
                    test ! -L "$home"
                    test "$(cd "$home" && pwd -P)" = "$home"
                    if [ ! -e "$parent" ]; then mkdir -- "$parent"; fi
                    test -d "$parent"
                    test ! -L "$parent"
                    test "$(cd "$parent" && pwd -P)" = "$parent"

                    if [ -e "$checkout" ]; then
                        test -d "$checkout"
                        test ! -L "$checkout"
                        test "$(cd "$checkout" && pwd -P)" = "$checkout"
                        test "$(git -C "$checkout" rev-parse --show-toplevel)" = "$checkout"
                        test "$(git -C "$checkout" remote get-url origin)" = "$repository"
                    else
                        test ! -L "$checkout"
                        git clone -- "$repository" "$checkout"
                    fi

                    document_root_path="$checkout/$document_root"
                    test -d "$document_root_path"
                    test ! -L "$document_root_path"
                    case "$(cd "$document_root_path" && pwd -P)" in
                        "$checkout"|"$checkout"/*) ;;
                        *) exit 1 ;;
                    esac
                    BASH,
            ),
            step: 'instance-source',
            errorCode: 'instance.clone_failed',
        );
    }

    public function removeInstance(Instance $instance): void
    {
        $instance->loadMissing(['app', 'node']);
        $repository = GitRepositoryOrigin::validate($instance->app->repository_url);
        $this->instanceCheckout($instance);
        $home = $this->paths->home($instance->node, \App\Domain\Nodes\RoleName::AppDev);

        $this->lockedExecute(
            node: $instance->node,
            command: new RemoteCommand(
                arguments: [
                    '/bin/bash',
                    '-seu',
                    '--',
                    $repository,
                    $instance->app->slug,
                    $home,
                    $this->gitPath($instance->node),
                ],
                input: <<<'BASH'
                    repository=$1
                    app=$2
                    home=$3
                    git_path=$4
                    git() { "$git_path" "$@"; }
                    checkout="$home/apps/$app"
                    test "$(basename "$checkout")" = "$app"

                    if [ ! -e "$checkout" ] && [ ! -L "$checkout" ]; then
                        exit 0
                    fi

                    test -d "$checkout"
                    test ! -L "$checkout"
                    test "$(cd "$checkout" && pwd -P)" = "$checkout"
                    test "$(git -C "$checkout" rev-parse --show-toplevel)" = "$checkout"
                    test "$(git -C "$checkout" remote get-url origin)" = "$repository"
                    registered=$(git -C "$checkout" worktree list --porcelain | awk '/^worktree / { print substr($0, 10) }')
                    test "$registered" = "$checkout"
                    find -P "$checkout" -depth -delete
                    BASH,
            ),
            step: 'instance-source-remove',
            errorCode: 'instance.remove_failed',
        );
    }

    public function convergeWorkspace(Workspace $workspace): void
    {
        $workspace->loadMissing(['instance.app', 'instance.node']);
        $instance = $workspace->instance;
        $repository = GitRepositoryOrigin::validate($instance->app->repository_url);
        $instanceCheckout = $this->instanceCheckout($instance);
        $checkout = $this->workspaceCheckout($workspace);
        $home = $this->paths->home($instance->node, \App\Domain\Nodes\RoleName::AppDev);

        $this->lockedExecute(
            node: $instance->node,
            command: new RemoteCommand(
                arguments: [
                    '/bin/bash',
                    '-seu',
                    '--',
                    $instanceCheckout,
                    $repository,
                    $checkout,
                    $workspace->branch,
                    $instance->document_root,
                    $home,
                    $this->gitPath($instance->node),
                ],
                input: <<<'BASH'
                    instance=$1
                    repository=$2
                    checkout=$3
                    branch=$4
                    document_root=$5
                    home=$6
                    git_path=$7
                    git() { "$git_path" "$@"; }
                    parent=$(dirname "$checkout")
                    orbit_root="$home/.orbit"
                    worktrees_root="$orbit_root/worktrees"
                    app_worktrees="$worktrees_root/$(basename "$instance")"
                    test "$checkout" = "$home/.orbit/worktrees/$(basename "$instance")/$(basename "$checkout")"
                    test "$parent" = "$app_worktrees"
                    test ! -L "$home"
                    test "$(cd "$home" && pwd -P)" = "$home"
                    test ! -L "$instance"
                    test "$(cd "$instance" && pwd -P)" = "$instance"
                    test "$(git -C "$instance" rev-parse --show-toplevel)" = "$instance"
                    test "$(git -C "$instance" remote get-url origin)" = "$repository"

                    if git -C "$instance" worktree list --porcelain | grep -Fx -- "worktree $checkout" >/dev/null; then
                        test -d "$checkout"
                        test ! -L "$checkout"
                        test "$(cd "$checkout" && pwd -P)" = "$checkout"
                        test "$(git -C "$checkout" rev-parse --show-toplevel)" = "$checkout"
                        test "$(git -C "$checkout" symbolic-ref --quiet --short HEAD)" = "$branch"
                    else
                        test ! -e "$checkout"
                        test ! -L "$checkout"
                        for managed_directory in "$orbit_root" "$worktrees_root" "$app_worktrees"; do
                            if [ ! -e "$managed_directory" ]; then mkdir -- "$managed_directory"; fi
                            test -d "$managed_directory"
                            test ! -L "$managed_directory"
                            test "$(cd "$managed_directory" && pwd -P)" = "$managed_directory"
                        done

                        if git -C "$instance" show-ref --verify --quiet "refs/heads/$branch"; then
                            git -C "$instance" worktree add -- "$checkout" "$branch"
                        else
                            git -C "$instance" worktree add -b "$branch" -- "$checkout" HEAD
                        fi
                    fi

                    document_root_path="$checkout/$document_root"
                    test -d "$document_root_path"
                    test ! -L "$document_root_path"
                    case "$(cd "$document_root_path" && pwd -P)" in
                        "$checkout"|"$checkout"/*) ;;
                        *) exit 1 ;;
                    esac
                    BASH,
            ),
            step: 'workspace-source',
            errorCode: 'workspace.worktree_failed',
        );
    }

    public function removeWorkspace(Workspace $workspace): void
    {
        $workspace->loadMissing(['instance.app', 'instance.node']);
        $instance = $workspace->instance;
        $repository = GitRepositoryOrigin::validate($instance->app->repository_url);
        $this->instanceCheckout($instance);
        $this->workspaceCheckout($workspace);
        $home = $this->paths->home($instance->node, \App\Domain\Nodes\RoleName::AppDev);

        $this->lockedExecute(
            node: $instance->node,
            command: new RemoteCommand(
                arguments: [
                    '/bin/bash',
                    '-seu',
                    '--',
                    $repository,
                    $instance->app->slug,
                    $workspace->name,
                    $workspace->branch,
                    $home,
                    $this->gitPath($instance->node),
                ],
                input: <<<'BASH'
                    repository=$1
                    app=$2
                    workspace=$3
                    branch=$4
                    home=$5
                    git_path=$6
                    git() { "$git_path" "$@"; }
                    instance="$home/apps/$app"
                    checkout="$home/.orbit/worktrees/$app/$workspace"
                    test "$checkout" = "$home/.orbit/worktrees/$(basename "$instance")/$(basename "$checkout")"
                    test ! -L "$home/.orbit"
                    test ! -L "$home/.orbit/worktrees"
                    test ! -L "$home/.orbit/worktrees/$(basename "$instance")"
                    test ! -L "$instance"
                    test "$(cd "$instance" && pwd -P)" = "$instance"
                    test "$(git -C "$instance" rev-parse --show-toplevel)" = "$instance"
                    test "$(git -C "$instance" remote get-url origin)" = "$repository"
                    registration=$(git -C "$instance" worktree list --porcelain)

                    if ! printf '%s\n' "$registration" | grep -Fx -- "worktree $checkout" >/dev/null; then
                        test ! -e "$checkout"
                        test ! -L "$checkout"
                        exit 0
                    fi

                    registered_branch=$(printf '%s\n' "$registration" | awk -v path="$checkout" '
                        $0 == "worktree " path { found=1; next }
                        found && /^branch refs\/heads\// { print substr($0, 19); exit }
                        found && /^worktree / { exit 42 }
                    ')
                    test "$registered_branch" = "$branch"
                    test -d "$checkout"
                    test ! -L "$checkout"
                    test "$(cd "$checkout" && pwd -P)" = "$checkout"
                    test "$(git -C "$checkout" rev-parse --show-toplevel)" = "$checkout"
                    test "$(git -C "$checkout" symbolic-ref --quiet --short HEAD)" = "$branch"
                    git -C "$instance" worktree remove --force -- "$checkout"
                    test ! -e "$checkout"
                    test ! -L "$checkout"
                    BASH,
            ),
            step: 'workspace-source-remove',
            errorCode: 'workspace.remove_failed',
        );
    }

    private function instanceCheckout(Instance $instance): string
    {
        $expected = $this->paths->instanceCheckout(
            $instance->node,
            \App\Domain\Nodes\RoleName::AppDev,
            $instance->app->slug,
            $instance->name,
        );

        if ($instance->checkout_path === $expected) {
            return $expected;
        }

        throw new ResourceOperationException(
            errorCode: 'instance.path_invalid',
            message: 'The stored Darwin instance checkout path is not managed by Orbit.',
        );
    }

    private function workspaceCheckout(Workspace $workspace): string
    {
        $expected = $this->paths->workspaceCheckout(
            $workspace->instance->node,
            $workspace->instance->app->slug,
            $workspace->name,
        );

        if ($workspace->checkout_path === $expected) {
            return $expected;
        }

        throw new ResourceOperationException(
            errorCode: 'workspace.path_unsupported',
            message: 'Darwin workspaces must use the managed Orbit worktree path.',
        );
    }

    private function lockedExecute(Node $node, RemoteCommand $command, string $step, string $errorCode): void
    {
        $this->lock->synchronized($node->id, function () use ($node, $command, $step, $errorCode): void {
            $connection = $this->connections->make($node);
            $result = $this->ssh->execute($connection, $this->guard->guard($command));

            if (! $result->succeeded()) {
                throw new RuntimeConvergenceException(
                    step: $step,
                    errorCode: $errorCode,
                    message: 'The macOS source operation failed.',
                    result: $result,
                );
            }
        });
    }

    private function gitPath(Node $node): string
    {
        return match ($node->architecture) {
            'arm64' => '/opt/homebrew/bin/git',
            'x86_64' => '/usr/local/bin/git',
            default => throw new ResourceOperationException(
                errorCode: 'instance.platform_unsupported',
                message: 'The Darwin architecture is not supported.',
            ),
        };
    }
}
