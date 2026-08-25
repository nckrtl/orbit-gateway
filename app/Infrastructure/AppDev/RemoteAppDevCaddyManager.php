<?php

declare(strict_types=1);

namespace App\Infrastructure\AppDev;

use App\Domain\AppDev\AppDevCaddyManager;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Models\Node;

final readonly class RemoteAppDevCaddyManager implements AppDevCaddyManager
{
    public function __construct(
        private AppDevSiteRepository $sites,
        private AppDevCaddyConfigRenderer $renderer,
        private AppDevSshExecutor $ssh,
    ) {}

    public function converge(Node $node): void
    {
        $configuration = $this->renderer->render($this->sites->forNode($node));
        $version = bin2hex(random_bytes(8));
        $encoded = base64_encode($configuration);
        $this->ssh->execute(
            $node,
            new RemoteCommand(
                arguments: ['bash', '-seu', '--', $version],
                input: <<<BASH
                    version=\$1
                    versions=/etc/caddy/orbit-versions
                    candidate="\$versions/\$version.candidate"
                    published="\$versions/\$version"
                    candidate_link="/etc/caddy/.Caddyfile.orbit-\$version"
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
                    source_main=\$(readlink -f /etc/caddy/Caddyfile)
                    test -f "\$source_main"
                    previous_fragments=\$(dirname "\$source_main")/fragments

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
                            sudo cp --preserve=mode,ownership -- "\$source_main" "\$candidate/fragments/unmanaged.caddy"
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
                    sudo mv -fT -- "\$candidate_link" /etc/caddy/Caddyfile
                    live_switched=1
                    sudo systemctl enable caddy
                    sudo systemctl reload-or-restart caddy
                    BASH,
            ),
            step: 'caddy-config',
            errorCode: 'app-dev.caddy_config_failed',
        );
    }
}
