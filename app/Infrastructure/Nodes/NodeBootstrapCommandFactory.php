<?php

declare(strict_types=1);

namespace App\Infrastructure\Nodes;

use App\Domain\Nodes\RoleName;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Models\Node;

final readonly class NodeBootstrapCommandFactory
{
    public function __construct(
        private SshKeyProvider $keys,
    ) {}

    public function make(Node $node): RemoteCommand
    {
        return $this->command($node);
    }

    public function makeWithPasswordlessSudo(Node $node): RemoteCommand
    {
        return $this->command($node, ['sudo', '-n', '--']);
    }

    /** @param list<string> $argumentPrefix */
    private function command(Node $node, array $argumentPrefix = []): RemoteCommand
    {
        $roles = $node->roles->pluck('role');
        $isAppDevelopment = $roles->contains(RoleName::AppDev);
        $isAppHost = $isAppDevelopment || $roles->contains(RoleName::AppProd);

        $arguments = [
            ...$argumentPrefix,
            'bash',
            '-seu',
            '--',
            $this->keys->publicKey(),
            $isAppDevelopment ? '1' : '0',
            $isAppHost ? '1' : '0',
            ...$this->packages($node),
        ];

        return new RemoteCommand(
            arguments: $arguments,
            input: <<<'BASH'
                if [ ! -r /etc/os-release ]; then
                    printf '%s\n' 'Orbit requires Ubuntu 26.04 Resolute.' >&2
                    exit 1
                fi

                if ! . /etc/os-release; then
                    printf '%s\n' 'Orbit requires Ubuntu 26.04 Resolute.' >&2
                    exit 1
                fi

                if [ "${ID:-}" != ubuntu ] || [ "${VERSION_CODENAME:-}" != resolute ]; then
                    printf '%s\n' 'Orbit requires Ubuntu 26.04 Resolute.' >&2
                    exit 1
                fi

                orbit_key=$1
                app_dev=$2
                app_host=$3
                shift 3

                export DEBIAN_FRONTEND=noninteractive
                apt-get update
                apt-get install --yes --no-install-recommends -- "$@"

                if ! id -u orbit >/dev/null 2>&1; then
                    useradd --create-home --shell /bin/bash orbit
                fi

                test "$(getent passwd orbit | cut -d: -f6)" = /home/orbit
                install -d -m 0700 -o orbit -g orbit /home/orbit
                install -d -m 0700 -o orbit -g orbit /home/orbit/.ssh /home/orbit/.orbit
                if [ "$app_dev" = 1 ]; then
                    install -d -m 0755 -o orbit -g orbit /home/orbit/apps /home/orbit/.orbit/worktrees
                    setfacl -m u:caddy:--x /home/orbit /home/orbit/apps /home/orbit/.orbit /home/orbit/.orbit/worktrees
                fi
                touch /home/orbit/.ssh/authorized_keys
                if ! grep -qxF "$orbit_key" /home/orbit/.ssh/authorized_keys; then
                    printf '%s\n' "$orbit_key" >> /home/orbit/.ssh/authorized_keys
                fi
                chown orbit:orbit /home/orbit/.ssh/authorized_keys
                chmod 0600 /home/orbit/.ssh/authorized_keys

                if [ "$app_host" = 1 ]; then
                    if { [ -e /opt/orbit ] || [ -L /opt/orbit ]; } \
                        && { [ -L /opt/orbit ] || [ ! -d /opt/orbit ] || [ "$(stat -c '%U:%G' /opt/orbit)" != 'root:root' ]; }; then
                        printf 'Orbit JavaScript runtime directory conflict: %s\n' /opt/orbit >&2
                        exit 1
                    fi

                    for directory in /opt/orbit/vite-plus /opt/orbit/bun; do
                        if { [ -e "$directory" ] || [ -L "$directory" ]; } \
                            && { [ -L "$directory" ] || [ ! -d "$directory" ] || [ "$(stat -c '%U:%G' "$directory")" != 'orbit:orbit' ]; }; then
                            printf 'Orbit JavaScript runtime directory conflict: %s\n' "$directory" >&2
                            exit 1
                        fi
                    done

                    install -d -m 0755 /opt/orbit
                    install -d -m 0755 -o orbit -g orbit /opt/orbit/vite-plus /opt/orbit/bun

                    sudo -u orbit -H env VP_HOME=/opt/orbit/vite-plus bash -o pipefail -lc 'curl -fsSL https://vite.plus | bash'
                    vp_binary=/opt/orbit/vite-plus/bin/vp
                    test -x "$vp_binary"
                    sudo -u orbit -H env VP_HOME=/opt/orbit/vite-plus "$vp_binary" env setup
                    sudo -u orbit -H env VP_HOME=/opt/orbit/vite-plus "$vp_binary" env on
                    sudo -u orbit -H env VP_HOME=/opt/orbit/vite-plus "$vp_binary" env install lts
                    sudo -u orbit -H env VP_HOME=/opt/orbit/vite-plus "$vp_binary" env default lts
                    sudo -u orbit -H env VP_HOME=/opt/orbit/vite-plus "$vp_binary" install -g --node lts pnpm
                    pnpm_binary=/opt/orbit/vite-plus/bin/pnpm
                    test -x "$pnpm_binary"

                    sudo -u orbit -H env BUN_INSTALL=/opt/orbit/bun bash -o pipefail -lc 'curl -fsSL https://bun.com/install | bash'
                    bun_binary=/opt/orbit/bun/bin/bun
                    test -x "$bun_binary"

                    chmod -R a+rX /opt/orbit/vite-plus /opt/orbit/bun

                    launcher_candidates=$(mktemp -d "/usr/local/bin/.orbit-js-runtime.XXXXXX")
                    published_paths=
                    rollback_javascript_runtime() {
                        runtime_status=$?

                        if [ "$runtime_status" -ne 0 ]; then
                            for published_path in $published_paths; do
                                rm -f -- "$published_path"
                            done
                        fi

                        rm -rf -- "$launcher_candidates"
                        return "$runtime_status"
                    }
                    trap rollback_javascript_runtime EXIT

                    for binary in vp node pnpm npm npx; do
                        target="/opt/orbit/vite-plus/bin/$binary"
                        candidate="$launcher_candidates/$binary"
                        test -x "$target"
                        printf '%s\n' \
                            '#!/bin/sh' \
                            'export VP_HOME=/opt/orbit/vite-plus' \
                            "exec \"$target\" \"\$@\"" > "$candidate"
                        chmod 0755 "$candidate"
                        chown root:root "$candidate"
                    done

                    for binary in vp node pnpm npm npx; do
                        launcher="/usr/local/bin/$binary"
                        candidate="$launcher_candidates/$binary"
                        if { [ -e "$launcher" ] || [ -L "$launcher" ]; } \
                            && { [ -L "$launcher" ] || [ ! -f "$launcher" ] \
                                || [ "$(stat -c '%U:%G' "$launcher")" != 'root:root' ] \
                                || [ "$(stat -c '%a' "$launcher")" != '755' ] \
                                || ! cmp -s "$launcher" "$candidate"; }; then
                            printf 'Orbit JavaScript runtime launcher conflict: %s\n' "$launcher" >&2
                            exit 1
                        fi
                    done

                    if { [ -e /usr/local/bin/bun ] || [ -L /usr/local/bin/bun ]; } \
                        && { [ ! -L /usr/local/bin/bun ] \
                            || [ "$(stat -c '%U:%G' /usr/local/bin/bun)" != 'root:root' ] \
                            || [ "$(readlink /usr/local/bin/bun)" != "$bun_binary" ]; }; then
                        printf 'Orbit JavaScript runtime link conflict: %s\n' /usr/local/bin/bun >&2
                        exit 1
                    fi

                    for binary in vp node pnpm npm npx; do
                        launcher="/usr/local/bin/$binary"
                        candidate="$launcher_candidates/$binary"

                        if ! { [ -e "$launcher" ] || [ -L "$launcher" ]; }; then
                            mv "$candidate" "$launcher"
                            published_paths="$published_paths $launcher"
                        fi
                    done

                    if ! { [ -e /usr/local/bin/bun ] || [ -L /usr/local/bin/bun ]; }; then
                        ln -s "$bun_binary" /usr/local/bin/bun
                        published_paths="$published_paths /usr/local/bin/bun"
                    fi

                    env VP_HOME=/opt/orbit/vite-plus /usr/local/bin/vp --version
                    /usr/local/bin/node --version
                    /usr/local/bin/pnpm --version
                    /usr/local/bin/npm --version
                    /usr/local/bin/npx --version
                    /usr/local/bin/bun --version

                    rm -rf -- "$launcher_candidates"
                    launcher_candidates=
                    published_paths=
                    trap - EXIT
                fi

                sudoers=$(mktemp)
                printf 'orbit ALL=(ALL) NOPASSWD:ALL\n' > "$sudoers"
                chmod 0440 "$sudoers"
                visudo -cf "$sudoers"
                install -m 0440 -o root -g root "$sudoers" /etc/sudoers.d/orbit
                rm -f "$sudoers"
                BASH,
        );
    }

    /** @return non-empty-list<string> */
    private function packages(Node $node): array
    {
        $packages = [
            'ca-certificates',
            'curl',
            'git',
            'gnupg',
            'openssh-client',
            'sudo',
            'ufw',
            'wireguard',
        ];
        $roles = $node->roles->pluck('role');

        if ($roles->contains(RoleName::AppDev) || $roles->contains(RoleName::AppProd)) {
            $packages = [
                ...$packages,
                'acl',
                'attr',
                'caddy',
                'composer',
                'docker.io',
                'openssl',
                'unzip',
            ];
        }

        if ($roles->contains(RoleName::Vpn)) {
            $packages = [...$packages, 'dnsmasq', 'openssl'];
        }

        return array_values(array_unique($packages));
    }
}
