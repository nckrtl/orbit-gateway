<?php

declare(strict_types=1);

namespace App\Infrastructure\AppDev;

use App\Infrastructure\Ssh\RemoteCommand;

final readonly class AppDevCaddyPublisher
{
    public function __construct(
        private string $versionsDirectory = '/etc/caddy/orbit-versions',
        private string $liveCaddyfilePath = '/etc/caddy/Caddyfile',
        private string $caddyServiceName = 'caddy',
    ) {}

    public function command(string $configuration, string $version): RemoteCommand
    {
        $encoded = base64_encode($configuration);

        return new RemoteCommand(
            arguments: [
                'bash',
                '-seu',
                '--',
                $version,
                $this->versionsDirectory,
                $this->liveCaddyfilePath,
                $this->caddyServiceName,
            ],
            input: <<<BASH
                version=\$1
                versions=\$2
                live_caddyfile=\$3
                caddy_service=\$4
                candidate="\$versions/\$version.candidate"
                published="\$versions/\$version"
                candidate_link="\$(dirname "\$live_caddyfile")/.Caddyfile.orbit-\$version"
                published_installed=0
                live_switched=0
                cleanup() {
                    sudo rm -rf -- "\$candidate" "\$candidate_link"
                    if [ "\$published_installed" = 1 ] && [ "\$live_switched" = 0 ]; then
                        sudo rm -rf -- "\$published"
                    fi
                }
                trap cleanup EXIT
                sudo install -d -o root -g caddy -m 0750 -- "\$versions" "\$candidate/fragments"
                source_main=\$(readlink -f "\$live_caddyfile")
                test -f "\$source_main"
                previous_fragments=\$(dirname "\$source_main")/fragments
                preserve_source_main=1

                case "\$source_main" in
                    "\$versions"/*/Caddyfile)
                        for fragment in "\$previous_fragments"/*.caddy; do
                            if [ ! -e "\$fragment" ] || [ "\$(basename "\$fragment")" = app-dev.caddy ]; then
                                continue
                            fi

                            sudo cp --preserve=mode,ownership -- "\$fragment" "\$candidate/fragments/"
                        done
                        ;;
                    *)
                        if [ "\$source_main" = "\$live_caddyfile" ]; then
                            current_md5=\$(md5sum -- "\$source_main" | awk '{print \$1}')
                            default_md5=\$(dpkg-query -W -f='\${Conffiles}\n' "\$caddy_service" | awk -v live_caddyfile="\$live_caddyfile" '\$1 == live_caddyfile { print \$2; exit }')

                            if [ -n "\$default_md5" ] && [ "\$current_md5" = "\$default_md5" ]; then
                                preserve_source_main=0
                            fi
                        fi

                        if [ "\$preserve_source_main" = 1 ]; then
                            sudo cp --preserve=mode,ownership -- "\$source_main" "\$candidate/fragments/unmanaged.caddy"
                        fi
                        ;;
                esac
                printf '%s' '{$encoded}' | base64 --decode | \
                    sudo tee "\$candidate/fragments/app-dev.caddy" >/dev/null
                printf 'import fragments/*.caddy\n' | sudo tee "\$candidate/Caddyfile" >/dev/null
                sudo chown -R root:caddy "\$candidate"
                sudo find "\$candidate" -type d -exec chmod 0750 {} +
                sudo find "\$candidate" -type f -exec chmod 0640 {} +
                sudo caddy validate --config "\$candidate/Caddyfile" --adapter caddyfile
                sudo mv -fT -- "\$candidate" "\$published"
                published_installed=1
                sudo ln -s -- "\$published/Caddyfile" "\$candidate_link"
                sudo mv -fT -- "\$candidate_link" "\$live_caddyfile"
                live_switched=1
                sudo systemctl enable "\$caddy_service"
                sudo systemctl reload-or-restart "\$caddy_service"
                BASH,
        );
    }
}
