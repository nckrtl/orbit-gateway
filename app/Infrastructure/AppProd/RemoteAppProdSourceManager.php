<?php

declare(strict_types=1);

namespace App\Infrastructure\AppProd;

use App\Domain\AppProd\AppProdSourceManager;
use App\Domain\SourceControl\GitRepositoryOrigin;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Models\Instance;

final readonly class RemoteAppProdSourceManager implements AppProdSourceManager
{
    public function __construct(
        private AppProdSshExecutor $ssh,
    ) {}

    public function converge(Instance $instance): void
    {
        $instance->loadMissing(['app', 'node']);
        $repository = GitRepositoryOrigin::validate($instance->app->repository_url);
        $arguments = [
            'bash',
            '-seu',
            '--',
            "orbit-{$instance->app->slug}",
            $instance->app->slug,
            $instance->name,
            $repository,
            $instance->checkout_path,
            $instance->document_root,
        ];
        $this->ssh->execute(
            $instance->node,
            new RemoteCommand(arguments: $arguments, input: $this->driftProbe()),
            step: 'app-prod-source-probe',
            errorCode: 'instance.repository_origin_drift',
        );
        $this->ssh->execute(
            $instance->node,
            new RemoteCommand(arguments: $arguments, input: $this->convergeScript()),
            step: 'app-prod-source',
            errorCode: 'app-prod.source_failed',
        );
    }

    public function remove(Instance $instance): void
    {
        $instance->loadMissing(['app', 'node']);
        $repository = GitRepositoryOrigin::validate($instance->app->repository_url);
        $this->ssh->execute(
            $instance->node,
            new RemoteCommand(
                arguments: [
                    'sudo',
                    'bash',
                    '-seu',
                    '--',
                    "orbit-{$instance->app->slug}",
                    $instance->app->slug,
                    $instance->name,
                    $repository,
                    $instance->checkout_path,
                ],
                input: <<<'BASH'
                    user=$1
                    slug=$2
                    instance=$3
                    repository=$4
                    checkout=$5
                    test "$user" = "orbit-$slug"
                    test "$checkout" = "/var/www/$slug/$instance"
                    test ! -L "/var/www/$slug"

                    if [ ! -e "$checkout" ]; then
                        exit 0
                    fi

                    test -d "$checkout"
                    test ! -L "$checkout"
                    test "$(stat -c %U "$checkout")" = "$user"
                    test "$(realpath -e "$checkout")" = "$checkout"
                    test "$(sudo -u "$user" -H -- git -C "$checkout" rev-parse --show-toplevel)" = "$checkout"
                    test "$(sudo -u "$user" -H -- git -C "$checkout" remote get-url origin)" = "$repository"
                    sudo -u "$user" -H -- rm -rf -- "$checkout"
                    BASH,
            ),
            step: 'app-prod-source-remove',
            errorCode: 'app-prod.source_remove_failed',
        );
    }

    private function driftProbe(): string
    {
        return <<<'BASH'
            user=$1
            slug=$2
            instance=$3
            repository=$4
            checkout=$5
            test "$user" = "orbit-$slug"
            test "$checkout" = "/var/www/$slug/$instance"
            test ! -L "/var/www/$slug"

            if [ ! -e "$checkout" ]; then
                exit 0
            fi

            test -d "$checkout"
            test ! -L "$checkout"
            test "$(realpath -e "$checkout")" = "$checkout"
            test "$(stat -c %U "$checkout")" = "$user"
            test "$(sudo -u "$user" -H -- git -C "$checkout" rev-parse --show-toplevel)" = "$checkout"
            test "$(sudo -u "$user" -H -- git -C "$checkout" remote get-url origin)" = "$repository"
            BASH;
    }

    private function convergeScript(): string
    {
        return <<<'BASH'
            user=$1
            slug=$2
            instance=$3
            repository=$4
            checkout=$5
            document_root=$6
            app_root="/var/www/$slug"
            test "$user" = "orbit-$slug"
            test "$checkout" = "$app_root/$instance"
            test -d "$app_root"
            test ! -L "$app_root"
            test "$(stat -c %U "$app_root")" = "$user"

            if [ ! -e "$checkout" ]; then
                sudo -u "$user" -H -- git clone -- "$repository" "$checkout"
            fi

            test -d "$checkout"
            test ! -L "$checkout"
            test "$(realpath -e "$checkout")" = "$checkout"
            test "$(stat -c %U "$checkout")" = "$user"
            test "$(sudo -u "$user" -H -- git -C "$checkout" rev-parse --show-toplevel)" = "$checkout"
            test "$(sudo -u "$user" -H -- git -C "$checkout" remote get-url origin)" = "$repository"
            sudo chmod 0700 -- "$checkout"
            if [ -f "$checkout/.env" ] && [ ! -L "$checkout/.env" ]; then
                sudo chmod 0600 -- "$checkout/.env"
            fi

            checkout_root=$(realpath -e "$checkout")
            sudo setfacl -P -R -m u:caddy:--- "$checkout_root"
            sudo find -P "$checkout_root" -type d -exec setfacl -m d:u:caddy:--- -- {} +
            document_root_path="$checkout/$document_root"
            test -d "$document_root_path"
            test ! -L "$document_root_path"
            document_root_real=$(realpath -e "$document_root_path")
            case "$document_root_real" in
                "$checkout_root"|"$checkout_root"/*) ;;
                *) exit 1 ;;
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
                    exit 1
                fi
                storage_target=$expected_target
            done < <(find -P "$document_root_real" -type l -print0)
            sudo setfacl -m u:caddy:--x /var/www "$app_root" "$checkout_root"
            sudo setfacl -P -R -m u:caddy:r-X "$document_root_real"
            sudo find -P "$document_root_real" -type d -exec setfacl -m d:u:caddy:r-x -- {} +
            if [ -n "$storage_target" ]; then
                sudo setfacl -m u:caddy:--x "$checkout_root/storage" "$checkout_root/storage/app"
                sudo setfacl -P -R -m u:caddy:r-X "$storage_target"
                sudo find -P "$storage_target" -type d -exec setfacl -m d:u:caddy:r-x -- {} +
            fi
            BASH;
    }
}
