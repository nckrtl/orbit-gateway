<?php

declare(strict_types=1);

namespace App\Infrastructure\Nodes;

use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshKeyProvider;
use App\Models\Node;

final readonly class NodeBootstrapCommandFactory
{
    /** @var non-empty-list<string> */
    private const array PACKAGES = [
        'ca-certificates',
        'curl',
        'gnupg',
        'openssh-client',
        'sudo',
        'ufw',
        'wireguard',
    ];

    public function __construct(
        private SshKeyProvider $keys,
    ) {}

    public function make(Node $node): RemoteCommand
    {
        return $this->command();
    }

    public function makeWithPasswordlessSudo(Node $node): RemoteCommand
    {
        return $this->command(['sudo', '-n', '--']);
    }

    /** @param list<string> $argumentPrefix */
    private function command(array $argumentPrefix = []): RemoteCommand
    {
        return new RemoteCommand(
            arguments: [
                ...$argumentPrefix,
                'bash',
                '-seu',
                '--',
                $this->keys->publicKey(),
                ...self::PACKAGES,
            ],
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
                shift

                export DEBIAN_FRONTEND=noninteractive
                apt-get update
                apt-get install --yes --no-install-recommends -- "$@"

                if ! id -u orbit >/dev/null 2>&1; then
                    useradd --create-home --shell /bin/bash orbit
                fi

                test "$(getent passwd orbit | cut -d: -f6)" = /home/orbit
                install -d -m 0700 -o orbit -g orbit /home/orbit
                install -d -m 0700 -o orbit -g orbit /home/orbit/.ssh /home/orbit/.orbit
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
}
