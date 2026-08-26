<?php

declare(strict_types=1);

namespace App\Infrastructure\AppDev;

use App\Domain\AppDev\AppDevSourceManager;
use App\Domain\AppDev\AppDevSourceOperationLock;
use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\SourceControl\GitRepositoryOrigin;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Models\Instance;
use App\Models\Workspace;

final readonly class RemoteAppDevSourceManager implements AppDevSourceManager
{
    public function __construct(
        private AppDevSshExecutor $ssh,
        private AppDevSourceOperationLock $lock,
    ) {}

    public function convergeInstance(Instance $instance): void
    {
        $instance->loadMissing(['app', 'node']);
        $repository = GitRepositoryOrigin::validate($instance->app->repository_url);
        $this->guardInstancePath($instance);
        $this->lock->synchronized($instance->node_id, function () use ($instance, $repository): void {
            $this->ssh->execute(
                $instance->node,
                new RemoteCommand(
                    arguments: [
                        'bash',
                        '-seu',
                        '--',
                        $repository,
                        $instance->checkout_path,
                        $instance->document_root,
                    ],
                    input: <<<'BASH'
                        repository=$1
                        checkout=$2
                        document_root=$3
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
                        prepare_caddy_access() {
                            checkout_root=$(realpath -e "$checkout")
                            test ! -L "$checkout"
                            test "$checkout_root" = "$checkout"
                            test "$checkout_root" = "$(git -C "$checkout" rev-parse --show-toplevel)"
                            setfacl -P -R -m u:caddy:--- "$checkout_root"
                            find -P "$checkout_root" -type d -exec setfacl -m d:u:caddy:--- -- {} +

                            document_root_path="$checkout/$document_root"
                            test -d "$document_root_path"
                            test ! -L "$document_root_path"
                            document_root_real=$(realpath -e "$document_root_path")
                            case "$document_root_real" in
                                "$checkout_root"|"$checkout_root"/*) ;;
                                *) return 1 ;;
                            esac
                            storage_target=
                            while IFS= read -r -d '' link; do
                                target=$(realpath -e "$link")
                                expected_link="$checkout_root/public/storage"
                                expected_target="$checkout_root/storage/app/public"
                                test "$document_root_real" = "$checkout_root/public"
                                test "$link" = "$expected_link"
                                test "$target" = "$expected_target"
                                test -d "$expected_target"
                                test ! -L "$checkout_root/storage"
                                test ! -L "$checkout_root/storage/app"
                                test ! -L "$expected_target"
                                if find -P "$expected_target" -type l -print -quit | grep -q .; then
                                    return 1
                                fi
                                storage_target=$expected_target
                            done < <(find -P "$document_root_real" -type l -print0)
                        }

                        grant_caddy_access() {
                            setfacl -m u:caddy:--x /home/orbit /home/orbit/apps "$checkout"

                            current=$checkout_root
                            if [ "$document_root_real" = "$checkout_root" ]; then
                                relative_parent=.
                            else
                                relative_parent=${document_root_real#"$checkout_root"/}
                                relative_parent=$(dirname "$relative_parent")
                            fi
                            if [ "$relative_parent" != . ]; then
                                IFS=/ read -r -a segments <<< "$relative_parent"
                                for segment in "${segments[@]}"; do
                                    current="$current/$segment"
                                    test ! -L "$current"
                                    setfacl -m u:caddy:--x "$current"
                                done
                            fi

                            setfacl -P -R -m u:caddy:r-X "$document_root_real"
                            find -P "$document_root_real" -type d -exec setfacl -m d:u:caddy:r-x -- {} +

                            if [ -n "$storage_target" ]; then
                                setfacl -m u:caddy:--x "$checkout_root/storage" "$checkout_root/storage/app"
                                setfacl -P -R -m u:caddy:r-X "$storage_target"
                                find -P "$storage_target" -type d -exec setfacl -m d:u:caddy:r-x -- {} +
                            fi
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
                        else
                            git clone -- "$repository" "$checkout"
                        fi

                        prepare_caddy_access
                        grant_caddy_access
                        BASH,
                ),
                step: 'instance-source',
                errorCode: 'instance.clone_failed',
            );
        });
    }

    public function removeInstance(Instance $instance): void
    {
        $instance->loadMissing(['app', 'node']);
        $repository = GitRepositoryOrigin::validate($instance->app->repository_url);
        $this->guardInstancePath($instance);
        $this->lock->synchronized($instance->node_id, function () use ($instance, $repository): void {
            $this->ssh->execute(
                $instance->node,
                new RemoteCommand(
                    arguments: [
                        'bash',
                        '-seu',
                        '--',
                        $repository,
                        $instance->checkout_path,
                    ],
                    input: <<<'BASH'
                        repository=$1
                        checkout=$2
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
                        test "$(git -C "$checkout" remote get-url origin)" = "$repository"
                        rm -rf -- "$checkout"
                        BASH,
                ),
                step: 'instance-source-remove',
                errorCode: 'instance.remove_failed',
            );
        });
    }

    public function convergeWorkspace(Workspace $workspace): void
    {
        $workspace->loadMissing(['instance.app', 'instance.node']);
        $repository = GitRepositoryOrigin::validate($workspace->instance->app->repository_url);
        $this->lock->synchronized($workspace->instance->node_id, function () use ($repository, $workspace): void {
            $traversalPaths = $this->workspaceTraversalPaths($workspace);
            $this->ssh->execute(
                $workspace->instance->node,
                new RemoteCommand(
                    arguments: [
                        'bash',
                        '-seu',
                        '--',
                        $workspace->instance->checkout_path,
                        $repository,
                        $workspace->checkout_path,
                        $workspace->branch,
                        $workspace->instance->document_root,
                        ...$traversalPaths,
                    ],
                    input: <<<'BASH'
                        instance=$1
                        repository=$2
                        checkout=$3
                        branch=$4
                        document_root=$5
                        shift 5
                        traversal_paths=("$@")
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
                        guard_workspace_path() {
                            relative=${checkout#/home/orbit/}
                            test "$relative" != "$checkout"
                            IFS=/ read -r -a path_segments <<< "$relative"
                            for segment in "${path_segments[@]}"; do
                                case "$segment" in
                                    ''|.|..|*[!A-Za-z0-9._-]*) return 1 ;;
                                esac
                            done
                            case "$checkout" in
                                /home/orbit/.orbit/worktrees/*) ;;
                                /home/orbit/.*|/home/orbit/apps|/home/orbit/apps/*) return 1 ;;
                                /home/orbit/*) ;;
                                *) return 1 ;;
                            esac
                        }
                        prepare_traversal_paths() {
                            state_directory=/home/orbit/.orbit/caddy-traversal-state
                            marker_name=user.orbit.caddy_traversal
                            install -d -m 0700 -- "$state_directory"
                            test -d "$state_directory"
                            test ! -L "$state_directory"
                            test "$(realpath -e "$state_directory")" = "$state_directory"
                            find "$state_directory" -maxdepth 1 -type f -name '.state.*' -delete
                            for path in "${traversal_paths[@]}"; do
                                case "$path" in
                                    /home/orbit|/home/orbit/*) ;;
                                    *) return 1 ;;
                                esac
                                case "$checkout" in
                                    "$path"/*) ;;
                                    *) return 1 ;;
                                esac
                                if [ ! -e "$path" ] && [ ! -L "$path" ]; then
                                    install -d -m 0700 -- "$path"
                                fi
                                test -d "$path"
                                test ! -L "$path"
                                test "$(realpath -e "$path")" = "$path"

                                case "$path" in
                                    /home/orbit|/home/orbit/apps|/home/orbit/.orbit|/home/orbit/.orbit/worktrees) ;;
                                    *)
                                        state_key=$(printf '%s' "$path" | sha256sum | cut -d' ' -f1)
                                        state="$state_directory/$state_key"
                                        if [ ! -e "$state" ] && [ ! -L "$state" ]; then
                                            if getfattr --only-values -n "$marker_name" -- "$path" >/dev/null 2>&1; then
                                                if getfacl -cp "$path" | grep -Eq '^user:caddy:--x$' \
                                                    && getfacl -cp "$path" | grep -Eq '^mask::[r-][w-]x$'; then
                                                    return 1
                                                fi
                                                setfattr -x "$marker_name" -- "$path"
                                            fi

                                            state_nonce=$(openssl rand -hex 32)
                                            printf '%s\n' "$state_nonce" | grep -Eq '^[0-9a-f]{64}$'
                                            temporary_state=$(mktemp "$state_directory/.state.XXXXXX")
                                            {
                                                printf '%s\n%s\n%s\n' "$path" "$(stat -c '%d:%i' "$path")" "$state_nonce"
                                                getfacl -cp "$path" | sed '/^default:/d'
                                            } > "$temporary_state"
                                            chmod 0600 "$temporary_state"
                                            setfattr -n "$marker_name" -v "$state_nonce" -- "$path"
                                            if ! mv -f -- "$temporary_state" "$state"; then
                                                setfattr -x "$marker_name" -- "$path"
                                                rm -f -- "$temporary_state"
                                                return 1
                                            fi
                                        fi
                                        test -f "$state"
                                        test ! -L "$state"
                                        test "$(stat -c '%a' "$state")" = 600
                                        test "$(sed -n '1p' "$state")" = "$path"
                                        state_identity=$(sed -n '2p' "$state")
                                        printf '%s\n' "$state_identity" | grep -Eq '^[0-9]+:[0-9]+$'
                                        test "$state_identity" = "$(stat -c '%d:%i' "$path")"
                                        state_nonce=$(sed -n '3p' "$state")
                                        printf '%s\n' "$state_nonce" | grep -Eq '^[0-9a-f]{64}$'
                                        test "$(getfattr --only-values -n "$marker_name" -- "$path" 2>/dev/null)" = "$state_nonce"
                                        tail -n +4 "$state" | setfacl --test --set-file=- "$path" >/dev/null
                                        ;;
                                esac

                                current_acl=$(getfacl -cp "$path")
                                traversal_mask=$(printf '%s\n' "$current_acl" | sed -n 's/^mask::\([rwx-]\{3\}\).*$/\1/p')
                                if [ -z "$traversal_mask" ]; then
                                    traversal_mask=$(printf '%s\n' "$current_acl" | sed -n 's/^group::\([rwx-]\{3\}\).*$/\1/p')
                                fi
                                printf '%s\n' "$traversal_mask" | grep -Eq '^[rwx-]{3}$'
                                traversal_mask="${traversal_mask%?}x"
                                setfacl -n -m "u:caddy:--x,m::$traversal_mask" "$path"
                                getfacl -cp "$path" | grep -Eq '^user:caddy:[r-][w-]x$'
                                getfacl -cp "$path" | grep -Fqx "mask::$traversal_mask"
                            done
                        }
                        prepare_caddy_access() {
                            checkout_root=$(realpath -e "$checkout")
                            test ! -L "$checkout"
                            test "$checkout_root" = "$checkout"
                            test "$checkout_root" = "$(git -C "$checkout" rev-parse --show-toplevel)"
                            setfacl -P -R -m u:caddy:--- "$checkout_root"
                            find -P "$checkout_root" -type d -exec setfacl -m d:u:caddy:--- -- {} +

                            document_root_path="$checkout/$document_root"
                            test -d "$document_root_path"
                            test ! -L "$document_root_path"
                            document_root_real=$(realpath -e "$document_root_path")
                            case "$document_root_real" in
                                "$checkout_root"|"$checkout_root"/*) ;;
                                *) return 1 ;;
                            esac
                            storage_target=
                            while IFS= read -r -d '' link; do
                                target=$(realpath -e "$link")
                                expected_link="$checkout_root/public/storage"
                                expected_target="$checkout_root/storage/app/public"
                                test "$document_root_real" = "$checkout_root/public"
                                test "$link" = "$expected_link"
                                test "$target" = "$expected_target"
                                test -d "$expected_target"
                                test ! -L "$checkout_root/storage"
                                test ! -L "$checkout_root/storage/app"
                                test ! -L "$expected_target"
                                if find -P "$expected_target" -type l -print -quit | grep -q .; then
                                    return 1
                                fi
                                storage_target=$expected_target
                            done < <(find -P "$document_root_real" -type l -print0)
                        }

                        grant_caddy_access() {
                            setfacl -m u:caddy:--x "$checkout"

                            current=$checkout_root
                            if [ "$document_root_real" = "$checkout_root" ]; then
                                relative_parent=.
                            else
                                relative_parent=${document_root_real#"$checkout_root"/}
                                relative_parent=$(dirname "$relative_parent")
                            fi
                            if [ "$relative_parent" != . ]; then
                                IFS=/ read -r -a segments <<< "$relative_parent"
                                for segment in "${segments[@]}"; do
                                    current="$current/$segment"
                                    test ! -L "$current"
                                    setfacl -m u:caddy:--x "$current"
                                done
                            fi

                            setfacl -P -R -m u:caddy:r-X "$document_root_real"
                            find -P "$document_root_real" -type d -exec setfacl -m d:u:caddy:r-x -- {} +

                            if [ -n "$storage_target" ]; then
                                setfacl -m u:caddy:--x "$checkout_root/storage" "$checkout_root/storage/app"
                                setfacl -P -R -m u:caddy:r-X "$storage_target"
                                find -P "$storage_target" -type d -exec setfacl -m d:u:caddy:r-x -- {} +
                            fi
                        }
                        guard_workspace_path
                        test ! -L "$instance"
                        test "$(realpath -e "$instance")" = "$(git -C "$instance" rev-parse --show-toplevel)"
                        test "$(git -C "$instance" remote get-url origin)" = "$repository"
                        prepare_traversal_paths

                        if git -C "$instance" worktree list --porcelain | grep -Fx -- "worktree $checkout" >/dev/null; then
                            test -d "$checkout"
                            test "$(git -C "$checkout" symbolic-ref --quiet --short HEAD)" = "$branch"
                        else
                            test ! -e "$checkout"
                            guard_checkout_parent "$checkout"
                            case "$(realpath -e "$(dirname "$checkout")")" in
                                /home/orbit|/home/orbit/*) ;;
                                *) exit 1 ;;
                            esac

                            if git -C "$instance" show-ref --verify --quiet "refs/heads/$branch"; then
                                git -C "$instance" worktree add -- "$checkout" "$branch"
                            else
                                git -C "$instance" worktree add -b "$branch" -- "$checkout" HEAD
                            fi
                        fi

                        prepare_caddy_access
                        grant_caddy_access
                        BASH,
                ),
                step: 'workspace-source',
                errorCode: 'workspace.worktree_failed',
            );
        });
    }

    public function removeWorkspace(Workspace $workspace): void
    {
        $workspace->loadMissing(['instance.app', 'instance.node']);
        $repository = GitRepositoryOrigin::validate($workspace->instance->app->repository_url);
        $this->lock->synchronized($workspace->instance->node_id, function () use ($repository, $workspace): void {
            $this->guardWorkspacePath($workspace);
            $releasePaths = $this->releasableWorkspaceTraversalPaths($workspace);
            $this->ssh->execute(
                $workspace->instance->node,
                new RemoteCommand(
                    arguments: [
                        'bash',
                        '-seu',
                        '--',
                        $workspace->instance->checkout_path,
                        $repository,
                        $workspace->checkout_path,
                        ...$releasePaths,
                    ],
                    input: <<<'BASH'
                            instance=$1
                            repository=$2
                            checkout=$3
                            shift 3
                            release_paths=("$@")
                            marker_name=user.orbit.caddy_traversal
                        parent=$(dirname "$checkout")
                        case "$parent" in
                            /home/orbit|/home/orbit/*) ;;
                            *) exit 1 ;;
                        esac
                        if [ -e "$parent" ] || [ -L "$parent" ]; then
                            test -d "$parent"
                            test ! -L "$parent"
                            case "$(realpath -e "$parent")" in
                                /home/orbit|/home/orbit/*) ;;
                                *) exit 1 ;;
                            esac
                        fi
                        test ! -L "$instance"
                        test "$(realpath -e "$instance")" = "$(git -C "$instance" rev-parse --show-toplevel)"
                        test "$(git -C "$instance" remote get-url origin)" = "$repository"

                        if ! git -C "$instance" worktree list --porcelain | grep -Fx -- "worktree $checkout" >/dev/null; then
                            test ! -e "$checkout"
                        else
                            git -C "$instance" worktree remove --force -- "$checkout"
                        fi

                        for path in "${release_paths[@]}"; do
                            case "$path" in
                                /home/orbit/*) ;;
                                *) exit 1 ;;
                                esac
                                state_directory=/home/orbit/.orbit/caddy-traversal-state
                                state_key=$(printf '%s' "$path" | sha256sum | cut -d' ' -f1)
                                state="$state_directory/$state_key"
                                if [ ! -e "$state" ] && [ ! -L "$state" ]; then
                                    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
                                        continue
                                    fi

                                    test -d "$path"
                                    test ! -L "$path"
                                    test "$(realpath -e "$path")" = "$path"
                                    if getfattr --only-values -n "$marker_name" -- "$path" >/dev/null 2>&1; then
                                        if getfacl -cp "$path" | grep -Eq '^user:caddy:--x$' \
                                            && getfacl -cp "$path" | grep -Eq '^mask::[r-][w-]x$'; then
                                            exit 1
                                        fi
                                        setfattr -x "$marker_name" -- "$path"
                                    fi
                                    continue
                                fi

                                if [ ! -e "$path" ] && [ ! -L "$path" ]; then
                                    test -d "$state_directory"
                                    test ! -L "$state_directory"
                                    test "$(realpath -e "$state_directory")" = "$state_directory"
                                    test -f "$state"
                                    test ! -L "$state"
                                    test "$(stat -c '%a' "$state")" = 600
                                    test "$(sed -n '1p' "$state")" = "$path"
                                    state_nonce=$(sed -n '3p' "$state")
                                    printf '%s\n' "$state_nonce" | grep -Eq '^[0-9a-f]{64}$'
                                    rm -f -- "$state"
                                    continue
                                fi
                                test -d "$state_directory"
                                test ! -L "$state_directory"
                                test "$(realpath -e "$state_directory")" = "$state_directory"
                                test -d "$path"
                            test ! -L "$path"
                            test "$(realpath -e "$path")" = "$path"
                            test -f "$state"
                            test ! -L "$state"
                            test "$(stat -c '%a' "$state")" = 600
                            test "$(sed -n '1p' "$state")" = "$path"
                            state_identity=$(sed -n '2p' "$state")
                            printf '%s\n' "$state_identity" | grep -Eq '^[0-9]+:[0-9]+$'
                            test "$state_identity" = "$(stat -c '%d:%i' "$path")"
                            state_nonce=$(sed -n '3p' "$state")
                            printf '%s\n' "$state_nonce" | grep -Eq '^[0-9a-f]{64}$'
                            tail -n +4 "$state" | setfacl --test --set-file=- "$path" >/dev/null
                            if current_nonce=$(getfattr --only-values -n "$marker_name" -- "$path" 2>/dev/null); then
                                test "$current_nonce" = "$state_nonce"
                            elif cmp -s <(tail -n +4 "$state") <(getfacl -cp "$path" | sed '/^default:/d'); then
                                rm -f -- "$state"
                                continue
                            else
                                exit 1
                            fi

                            if ! cmp -s <(tail -n +4 "$state") <(getfacl -cp "$path" | sed '/^default:/d'); then
                                getfacl -cp "$path" | grep -Eq '^user:caddy:--x$'
                                getfacl -cp "$path" | grep -Eq '^mask::[r-][w-]x$'
                                tail -n +4 "$state" | setfacl --set-file=- "$path"
                                cmp -s <(tail -n +4 "$state") <(getfacl -cp "$path" | sed '/^default:/d')
                            fi
                            setfattr -x "$marker_name" -- "$path"
                            rm -f -- "$state"
                        done
                        BASH,
                ),
                step: 'workspace-source-remove',
                errorCode: 'workspace.remove_failed',
            );
        });
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

    /** @return list<string> */
    private function workspaceTraversalPaths(Workspace $workspace): array
    {
        $this->guardWorkspacePath($workspace);
        $parent = dirname($workspace->checkout_path);
        $relativeParent = mb_substr($parent, mb_strlen('/home/orbit'));
        $segments = array_values(array_filter(explode('/', $relativeParent)));
        $paths = ['/home/orbit'];
        $path = '/home/orbit';

        foreach ($segments as $segment) {
            $path .= "/{$segment}";
            $paths[] = $path;
        }

        return $paths;
    }

    /** @return list<string> */
    private function releasableWorkspaceTraversalPaths(Workspace $workspace): array
    {
        $remainingPaths = Workspace::query()
            ->with('instance')
            ->whereKeyNot($workspace->id)
            ->get()
            ->filter(
                static fn (Workspace $other): bool => $other->instance->node_id === $workspace->instance->node_id,
            )
            ->flatMap($this->workspaceTraversalPaths(...))
            ->unique()
            ->all();
        $fixedPaths = ['/home/orbit', '/home/orbit/apps', '/home/orbit/.orbit', '/home/orbit/.orbit/worktrees'];
        $releasePaths = array_diff($this->workspaceTraversalPaths($workspace), $remainingPaths, $fixedPaths);

        return array_values(array_reverse($releasePaths));
    }

    private function guardWorkspacePath(Workspace $workspace): void
    {
        $path = $workspace->checkout_path;
        $relative = mb_substr($path, mb_strlen('/home/orbit/'));
        $segments = explode('/', $relative);
        $protected = preg_match('#\A/home/orbit/(?:apps(?:/|\z)|\.(?!orbit/worktrees/))#', $path) === 1;
        $segmentsAreSafe = collect($segments)->every(
            static fn (string $segment): bool => (
                $segment !== ''
                && $segment !== '.'
                && $segment !== '..'
                && preg_match('/\A[A-Za-z0-9._-]+\z/', $segment) === 1
            ),
        );

        if (str_starts_with($path, '/home/orbit/') && ! $protected && $segmentsAreSafe) {
            return;
        }

        throw new RuntimeConvergenceException(
            step: 'workspace-source-path',
            errorCode: 'workspace.checkout_path_unsafe',
            message: "Workspace [{$workspace->name}] has an unsafe checkout path.",
        );
    }
}
