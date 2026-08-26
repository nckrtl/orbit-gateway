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
        $arguments = [
            ...$argumentPrefix,
            'bash',
            '-seu',
            '--',
            $this->keys->publicKey(),
            $node->roles->pluck('role')->contains(RoleName::AppDev) ? '1' : '0',
            ...$this->packages($node),
        ];

        return new RemoteCommand(
            arguments: $arguments,
            input: <<<'BASH'
                orbit_key=$1
                app_dev=$2
                shift 2

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
