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
        private string $lockPath = '/run/lock/orbit-caddy.lock',
    ) {}

    public function command(string $configuration, string $version): RemoteCommand
    {
        $encoded = base64_encode($configuration);

        return new RemoteCommand(
            arguments: [
                'sudo',
                'bash',
                '-seu',
                '--',
                $version,
                $this->versionsDirectory,
                $this->liveCaddyfilePath,
                $this->caddyServiceName,
                $this->lockPath,
            ],
            input: <<<BASH
                version=\$1
                versions=\$2
                live_caddyfile=\$3
                caddy_service=\$4
                lock=\$5
                exec 9>"\$lock"
                flock -w 30 9
                candidate="\$versions/\$version.candidate"
                published="\$versions/\$version"
                candidate_link="\$(dirname "\$live_caddyfile")/.Caddyfile.orbit-\$version"
                rollback_link="\$(dirname "\$live_caddyfile")/.Caddyfile.orbit-rollback-\$version"
                rollback_file="\$(dirname "\$live_caddyfile")/.Caddyfile.orbit-rollback-file-\$version"
                previous_main="\$versions/.previous-main.\$version"
                trap 'rm -rf -- "\$candidate"; rm -f -- "\$candidate_link" "\$rollback_link" "\$rollback_file" "\$previous_main"' EXIT
                install -d -o root -g caddy -m 0750 -- "\$versions" "\$candidate/fragments"
                source_main=\$(readlink -f "\$live_caddyfile")
                test -f "\$source_main"
                cp -a -- "\$source_main" "\$previous_main"
                previous_fragments=\$(dirname "\$source_main")/fragments
                previous_target=
                if [ -L "\$live_caddyfile" ]; then
                    previous_target=\$(readlink "\$live_caddyfile")
                fi
                preserve_source_main=1

                case "\$source_main" in
                    "\$versions"/*/Caddyfile)
                        for fragment in "\$previous_fragments"/*.caddy; do
                            if [ ! -e "\$fragment" ] || [ "\$(basename "\$fragment")" = app-dev.caddy ]; then
                                continue
                            fi

                            cp --preserve=mode,ownership -- "\$fragment" "\$candidate/fragments/"
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
                            cp --preserve=mode,ownership -- "\$source_main" "\$candidate/fragments/unmanaged.caddy"
                        fi
                        ;;
                esac
                printf '%s' '{$encoded}' | base64 --decode | \
                    tee "\$candidate/fragments/app-dev.caddy" >/dev/null
                printf 'import %s/fragments/*.caddy\n' "\$candidate" > "\$candidate/Caddyfile"
                chown -R root:caddy "\$candidate"
                find "\$candidate" -type d -exec chmod 0750 {} +
                find "\$candidate" -type f -exec chmod 0640 {} +

                if [ -f "\$previous_fragments/app-dev.caddy" ] && cmp -s -- "\$candidate/fragments/app-dev.caddy" "\$previous_fragments/app-dev.caddy"; then
                    exit 0
                fi

                caddy validate --config "\$candidate/Caddyfile" --adapter caddyfile
                printf 'import %s/%s/fragments/*.caddy\n' "\$versions" "\$version" > "\$candidate/Caddyfile"
                mv -fT -- "\$candidate" "\$published"
                ln -s -- "\$published/Caddyfile" "\$candidate_link"
                mv -fT -- "\$candidate_link" "\$live_caddyfile"
                if ! systemctl enable "\$caddy_service" || ! systemctl reload-or-restart "\$caddy_service"; then
                    if [ -n "\$previous_target" ]; then
                        ln -s -- "\$previous_target" "\$rollback_link"
                        mv -fT -- "\$rollback_link" "\$live_caddyfile"
                    else
                        cp -a -- "\$previous_main" "\$rollback_file"
                        mv -fT -- "\$rollback_file" "\$live_caddyfile"
                    fi
                    systemctl reload-or-restart "\$caddy_service" || true
                    rm -rf -- "\$published"
                    exit 1
                fi
                BASH,
        );
    }

    public function removeCommand(string $version): RemoteCommand
    {
        return $this->fragmentRemovalCommand($version, 'app-dev.caddy');
    }

    private function fragmentRemovalCommand(string $version, string $ownedFragment): RemoteCommand
    {
        return new RemoteCommand(
            arguments: [
                'sudo',
                'bash',
                '-seu',
                '--',
                $version,
                $this->versionsDirectory,
                $this->liveCaddyfilePath,
                $this->caddyServiceName,
                $this->lockPath,
                $ownedFragment,
            ],
            input: <<<'BASH'
                version=$1
                versions=$2
                live_caddyfile=$3
                caddy_service=$4
                lock=$5
                owned_fragment=$6
                exec 9>"$lock"
                flock -w 30 9
                source_main=$(readlink -f "$live_caddyfile")
                test -f "$source_main"
                current_fragments=$(dirname "$source_main")/fragments
                test ! -f "$current_fragments/app-dev.caddy" && exit 0
                candidate="$versions/$version.candidate"
                published="$versions/$version"
                candidate_link="$(dirname "$live_caddyfile")/.Caddyfile.orbit-$version"
                rollback_link="$(dirname "$live_caddyfile")/.Caddyfile.orbit-rollback-$version"
                rollback_file="$(dirname "$live_caddyfile")/.Caddyfile.orbit-rollback-file-$version"
                previous_main="$versions/.previous-main.$version"
                install -d -o root -g caddy -m 0750 -- "$versions"
                cp -a -- "$source_main" "$previous_main"
                previous_target=
                if [ -L "$live_caddyfile" ]; then
                    previous_target=$(readlink "$live_caddyfile")
                fi
                trap 'rm -rf -- "$candidate"; rm -f -- "$candidate_link" "$rollback_link" "$rollback_file" "$previous_main"' EXIT
                install -d -o root -g caddy -m 0750 -- "$candidate/fragments"
                for fragment in "$current_fragments"/*.caddy; do
                    if [ ! -e "$fragment" ] || [ "$(basename "$fragment")" = "$owned_fragment" ]; then
                        continue
                    fi
                    cp --preserve=mode,ownership -- "$fragment" "$candidate/fragments/"
                done
                printf 'import %s/fragments/*.caddy\n' "$candidate" > "$candidate/Caddyfile"
                chown -R root:caddy "$candidate"
                find "$candidate" -type d -exec chmod 0750 {} +
                find "$candidate" -type f -exec chmod 0640 {} +
                caddy validate --config "$candidate/Caddyfile" --adapter caddyfile
                printf 'import %s/%s/fragments/*.caddy\n' "$versions" "$version" > "$candidate/Caddyfile"
                mv -fT -- "$candidate" "$published"
                ln -s -- "$published/Caddyfile" "$candidate_link"
                mv -fT -- "$candidate_link" "$live_caddyfile"
                if ! systemctl reload-or-restart "$caddy_service"; then
                    if [ -n "$previous_target" ]; then
                        ln -s -- "$previous_target" "$rollback_link"
                        mv -fT -- "$rollback_link" "$live_caddyfile"
                    else
                        cp -a -- "$previous_main" "$rollback_file"
                        mv -fT -- "$rollback_file" "$live_caddyfile"
                    fi
                    systemctl reload-or-restart "$caddy_service" || true
                    rm -rf -- "$published"
                    exit 1
                fi
                BASH,
        );
    }
}
