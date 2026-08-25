<?php

declare(strict_types=1);

namespace App\Infrastructure\AppDev;

use App\Domain\AppDev\AppDevSourceManager;
use App\Domain\AppDev\RuntimeConvergenceException;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Models\Instance;
use App\Models\Workspace;

final readonly class RemoteAppDevSourceManager implements AppDevSourceManager
{
    public function __construct(
        private AppDevSshExecutor $ssh,
    ) {}

    public function convergeInstance(Instance $instance): void
    {
        $instance->loadMissing(['app', 'node']);
        $this->guardInstancePath($instance);
        $this->ssh->execute(
            $instance->node,
            new RemoteCommand(
                arguments: [
                    'bash',
                    '-seu',
                    '--',
                    $instance->app->repository_url,
                    $instance->checkout_path,
                ],
                input: <<<'BASH'
                    repository=$1
                    checkout=$2
                    guard_checkout_parent() {
                        parent=$(dirname "$1")
                        case "$parent" in
                            /home/orbit|/home/orbit/*) ;;
                            *) return 1 ;;
                        esac

                        existing_parent=$parent
                        while [ ! -e "$existing_parent" ] && [ ! -L "$existing_parent" ]; do
                            existing_parent=$(dirname "$existing_parent")
                        done
                        test ! -L "$existing_parent"
                        case "$(realpath -e "$existing_parent")" in
                            /home/orbit|/home/orbit/*) ;;
                            *) return 1 ;;
                        esac

                        current=/home/orbit
                        IFS=/ read -r -a segments <<< "${parent#/home/orbit/}"
                        for segment in "${segments[@]}"; do
                            current="$current/$segment"
                            if [ -e "$current" ] || [ -L "$current" ]; then
                                test ! -L "$current"
                            fi
                        done
                    }
                    guard_checkout_parent "$checkout"
                    install -d -m 0755 -- /home/orbit/apps "$(dirname "$checkout")"
                    case "$(realpath -e "$(dirname "$checkout")")" in
                        /home/orbit|/home/orbit/*) ;;
                        *) exit 1 ;;
                    esac

                    if [ -e "$checkout" ]; then
                        test ! -L "$checkout"
                        test -d "$checkout/.git"
                        test "$(realpath -e "$checkout")" = "$(git -C "$checkout" rev-parse --show-toplevel)"
                        test "$(git -C "$checkout" remote get-url origin)" = "$repository"
                        exit 0
                    fi

                    git clone -- "$repository" "$checkout"
                    BASH,
            ),
            step: 'instance-source',
            errorCode: 'instance.clone_failed',
        );
    }

    public function removeInstance(Instance $instance): void
    {
        $instance->loadMissing(['app', 'node']);
        $this->guardInstancePath($instance);
        $this->ssh->execute(
            $instance->node,
            new RemoteCommand(
                arguments: ['bash', '-seu', '--', $instance->checkout_path],
                input: <<<'BASH'
                    checkout=$1
                    parent=$(dirname "$checkout")

                    test ! -L "$parent"
                    case "$(realpath -e "$parent")" in
                        /home/orbit|/home/orbit/*) ;;
                        *) exit 1 ;;
                    esac

                    if [ ! -e "$checkout" ]; then
                        exit 0
                    fi

                    test ! -L "$checkout"
                    test "$(realpath -e "$checkout")" = "$(git -C "$checkout" rev-parse --show-toplevel)"
                    rm -rf -- "$checkout"
                    BASH,
            ),
            step: 'instance-source-remove',
            errorCode: 'instance.remove_failed',
        );
    }

    public function convergeWorkspace(Workspace $workspace): void
    {
        $workspace->loadMissing('instance.node');
        $this->ssh->execute(
            $workspace->instance->node,
            new RemoteCommand(
                arguments: [
                    'bash',
                    '-seu',
                    '--',
                    $workspace->instance->checkout_path,
                    $workspace->checkout_path,
                    $workspace->branch,
                ],
                input: <<<'BASH'
                    instance=$1
                    checkout=$2
                    branch=$3
                    guard_checkout_parent() {
                        parent=$(dirname "$1")
                        case "$parent" in
                            /home/orbit|/home/orbit/*) ;;
                            *) return 1 ;;
                        esac

                        existing_parent=$parent
                        while [ ! -e "$existing_parent" ] && [ ! -L "$existing_parent" ]; do
                            existing_parent=$(dirname "$existing_parent")
                        done
                        test ! -L "$existing_parent"
                        case "$(realpath -e "$existing_parent")" in
                            /home/orbit|/home/orbit/*) ;;
                            *) return 1 ;;
                        esac

                        current=/home/orbit
                        IFS=/ read -r -a segments <<< "${parent#/home/orbit/}"
                        for segment in "${segments[@]}"; do
                            current="$current/$segment"
                            if [ -e "$current" ] || [ -L "$current" ]; then
                                test ! -L "$current"
                            fi
                        done
                    }
                    test ! -L "$instance"
                    test "$(realpath -e "$instance")" = "$(git -C "$instance" rev-parse --show-toplevel)"

                    if git -C "$instance" worktree list --porcelain | grep -Fx -- "worktree $checkout" >/dev/null; then
                        test -d "$checkout"
                        test "$(git -C "$checkout" symbolic-ref --quiet --short HEAD)" = "$branch"
                        exit 0
                    fi

                    test ! -e "$checkout"
                    guard_checkout_parent "$checkout"
                    install -d -m 0755 -- "$(dirname "$checkout")"
                    case "$(realpath -e "$(dirname "$checkout")")" in
                        /home/orbit|/home/orbit/*) ;;
                        *) exit 1 ;;
                    esac

                    if git -C "$instance" show-ref --verify --quiet "refs/heads/$branch"; then
                        git -C "$instance" worktree add -- "$checkout" "$branch"
                    else
                        git -C "$instance" worktree add -b "$branch" -- "$checkout" HEAD
                    fi
                    BASH,
            ),
            step: 'workspace-source',
            errorCode: 'workspace.worktree_failed',
        );
    }

    public function removeWorkspace(Workspace $workspace): void
    {
        $workspace->loadMissing('instance.node');
        $this->ssh->execute(
            $workspace->instance->node,
            new RemoteCommand(
                arguments: [
                    'bash',
                    '-seu',
                    '--',
                    $workspace->instance->checkout_path,
                    $workspace->checkout_path,
                ],
                input: <<<'BASH'
                    instance=$1
                    checkout=$2
                    parent=$(dirname "$checkout")
                    case "$parent" in
                        /home/orbit|/home/orbit/*) ;;
                        *) exit 1 ;;
                    esac
                    test ! -L "$parent"
                    case "$(realpath -e "$parent")" in
                        /home/orbit|/home/orbit/*) ;;
                        *) exit 1 ;;
                    esac
                    test ! -L "$instance"
                    test "$(realpath -e "$instance")" = "$(git -C "$instance" rev-parse --show-toplevel)"

                    if ! git -C "$instance" worktree list --porcelain | grep -Fx -- "worktree $checkout" >/dev/null; then
                        test ! -e "$checkout"
                        exit 0
                    fi

                    git -C "$instance" worktree remove --force -- "$checkout"
                    BASH,
            ),
            step: 'workspace-source-remove',
            errorCode: 'workspace.remove_failed',
        );
    }

    private function guardInstancePath(Instance $instance): void
    {
        $expected = "/home/orbit/apps/{$instance->app->slug}";

        if (
            preg_match('/\A\/home\/orbit\/apps\/[A-Za-z0-9_-]+\z/', $expected) === 1
            && $instance->checkout_path === $expected
        ) {
            return;
        }

        throw new RuntimeConvergenceException(
            step: 'instance-source-path',
            errorCode: 'instance.checkout_path_unsafe',
            message: "Instance [{$instance->name}] has an unsafe checkout path.",
        );
    }
}
