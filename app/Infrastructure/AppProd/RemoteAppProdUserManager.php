<?php

declare(strict_types=1);

namespace App\Infrastructure\AppProd;

use App\Domain\AppProd\AppProdUserManager;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Models\Instance;

final readonly class RemoteAppProdUserManager implements AppProdUserManager
{
    public function __construct(
        private AppProdSshExecutor $ssh,
    ) {}

    public function converge(Instance $instance): void
    {
        $instance->loadMissing(['app', 'node']);
        $user = "orbit-{$instance->app->slug}";
        $this->ssh->execute(
            $instance->node,
            new RemoteCommand(
                arguments: ['bash', '-seu', '--', $user, $instance->app->slug],
                input: <<<'BASH'
                    user=$1
                    slug=$2
                    app_root="/var/www/$slug"
                    test "$user" = "orbit-$slug"
                    test "${#user}" -le 32

                    if getent passwd "$user" >/dev/null; then
                        entry=$(getent passwd "$user")
                        actual_home=$(printf '%s' "$entry" | cut -d: -f6)
                        actual_shell=$(printf '%s' "$entry" | cut -d: -f7)
                        test "$actual_home" = "$app_root"
                        test "$actual_shell" = /usr/sbin/nologin
                    else
                        sudo useradd --system --user-group --home-dir "$app_root" --shell /usr/sbin/nologin -- "$user"
                    fi

                    if [ -e "$app_root" ] || [ -L "$app_root" ]; then
                        test -d "$app_root"
                        test ! -L "$app_root"
                        test "$(stat -c %U "$app_root")" = "$user"
                        test "$(stat -c %G "$app_root")" = "$user"
                        sudo chmod 0700 -- "$app_root"
                    else
                        sudo install -d -o "$user" -g "$user" -m 0700 -- "$app_root"
                    fi
                    BASH,
            ),
            step: 'app-prod-user',
            errorCode: 'app-prod.user_failed',
        );
    }

    public function remove(Instance $instance): void
    {
        $instance->loadMissing(['app', 'node']);
        $user = "orbit-{$instance->app->slug}";
        $this->ssh->execute(
            $instance->node,
            new RemoteCommand(
                arguments: ['sudo', 'bash', '-seu', '--', $user, $instance->app->slug],
                input: <<<'BASH'
                    user=$1
                    slug=$2
                    app_root="/var/www/$slug"
                    test "$user" = "orbit-$slug"
                    test ! -L "$app_root"

                    if ! getent passwd "$user" >/dev/null; then
                        exit 0
                    fi

                    entry=$(getent passwd "$user")
                    test "$(printf '%s' "$entry" | cut -d: -f6)" = "$app_root"
                    test "$(printf '%s' "$entry" | cut -d: -f7)" = /usr/sbin/nologin
                    test -d "$app_root"
                    test "$(stat -c %U "$app_root")" = "$user"
                    test "$(stat -c %G "$app_root")" = "$user"
                    test -z "$(pgrep -u "$user" || true)"
                    if findmnt -rn -o TARGET | awk -v root="$app_root" '
                        $0 == root || index($0, root "/") == 1 { found=1 }
                        END { exit found ? 0 : 1 }
                    '; then
                        exit 1
                    fi
                    test -z "$(find -P "$app_root" -xdev -mindepth 1 ! -user "$user" -print -quit)"
                    test -z "$(find -P "$app_root" -xdev -mindepth 1 ! -group "$user" -print -quit)"
                    sudo -u "$user" -H -- find -P "$app_root" -xdev -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
                    test -z "$(find -P "$app_root" -xdev -mindepth 1 -maxdepth 1 -print -quit)"
                    userdel -- "$user"
                    rmdir -- "$app_root"
                    BASH,
            ),
            step: 'app-prod-user-remove',
            errorCode: 'app-prod.user_remove_failed',
        );
    }
}
