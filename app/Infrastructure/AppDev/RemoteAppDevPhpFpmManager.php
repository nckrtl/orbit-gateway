<?php

declare(strict_types=1);

namespace App\Infrastructure\AppDev;

use App\Domain\AppDev\AppDevPhpFpmManager;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Models\Node;
use App\Rules\SupportedPhpVersion;
use Illuminate\Support\Collection;

final readonly class RemoteAppDevPhpFpmManager implements AppDevPhpFpmManager
{
    public function __construct(
        private AppDevSiteRepository $sites,
        private AppDevPhpFpmConfigRenderer $renderer,
        private AppDevSshExecutor $ssh,
    ) {}

    public function converge(Node $node): void
    {
        $desiredSites = $this->sites->forNode($node);
        $desiredVersions = $desiredSites
            ->map(static fn (AppDevSite $site): string => $site->phpVersion)
            ->unique()
            ->values();
        $supportedVersions = collect(SupportedPhpVersion::all());
        $unsupportedVersion = $desiredVersions->diff($supportedVersions)->first();

        if (is_string($unsupportedVersion)) {
            throw new \App\Domain\AppDev\RuntimeConvergenceException(
                step: 'php-version',
                errorCode: 'app-dev.php_version_unsupported',
                message: "PHP version [{$unsupportedVersion}] is not supported.",
            );
        }

        $installedVersions = $this->installedVersions($node);

        foreach ($desiredVersions as $version) {
            $this->installVersion($node, $version);
        }

        $versions = $installedVersions
            ->merge($desiredVersions)
            ->unique()
            ->sort()
            ->values();

        foreach ($versions as $version) {
            $configuration = $this->renderer->render(
                $desiredSites->where('phpVersion', $version)->values(),
            );
            $this->publishVersion($node, $version, $configuration);
        }
    }

    /** @return Collection<int, string> */
    private function installedVersions(Node $node): Collection
    {
        $result = $this->ssh->execute(
            $node,
            new RemoteCommand(
                arguments: ['bash', '-seu'],
                input: <<<'BASH'
                    for path in /etc/php/*/fpm/pool.d/orbit-scopes.conf; do
                        if [ -e "$path" ]; then
                            basename "$(dirname "$(dirname "$(dirname "$path")")")"
                        fi
                    done
                    BASH,
            ),
            step: 'php-fpm-discover',
            errorCode: 'app-dev.php_fpm_discovery_failed',
        );
        $versions = preg_split('/\R/', trim($result->stdout));

        return collect(is_array($versions) ? $versions : [])
            ->filter(static fn (string $version): bool => preg_match('/\A[0-9]+\.[0-9]+\z/', $version) === 1)
            ->values();
    }

    private function installVersion(Node $node, string $version): void
    {
        $this->ssh->execute(
            $node,
            new RemoteCommand(
                arguments: ['bash', '-seu', '--', $version],
                input: <<<'BASH'
                    version=$1

                    if command -v "php-fpm$version" >/dev/null 2>&1; then
                        exit 0
                    fi

                    sudo env DEBIAN_FRONTEND=noninteractive apt-get update
                    sudo env DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends -- \
                        "php$version-cli" \
                        "php$version-curl" \
                        "php$version-fpm" \
                        "php$version-intl" \
                        "php$version-mbstring" \
                        "php$version-sqlite3" \
                        "php$version-xml" \
                        "php$version-zip"
                    BASH,
            ),
            step: 'php-fpm-install',
            errorCode: 'app-dev.php_install_failed',
        );
    }

    private function publishVersion(Node $node, string $version, string $configuration): void
    {
        $this->ssh->execute(
            $node,
            new RemoteCommand(
                arguments: ['bash', '-seu', '--', $version],
                input: $this->publishScript($configuration),
            ),
            step: 'php-fpm-config',
            errorCode: 'app-dev.php_fpm_config_failed',
        );
    }

    private function publishScript(string $configuration): string
    {
        $encoded = base64_encode($configuration);

        return <<<BASH
            version=\$1
            pool_directory="/etc/php/\$version/fpm/pool.d"
            main_configuration="/etc/php/\$version/fpm/php-fpm.conf"
            managed_configuration="\$pool_directory/orbit-scopes.conf"
            temporary_directory=\$(mktemp -d)
            trap 'rm -rf -- "\$temporary_directory"' EXIT
            install -d -m 0755 -- "\$temporary_directory/pool.d"

            for pool in "\$pool_directory"/*.conf; do
                if [ ! -e "\$pool" ] || [ "\$pool" = "\$managed_configuration" ]; then
                    continue
                fi

                cp -- "\$pool" "\$temporary_directory/pool.d/"
            done

            printf '%s' '{$encoded}' | base64 --decode > "\$temporary_directory/pool.d/orbit-scopes.conf"
            awk -v managed_include="include=\$temporary_directory/pool.d/*.conf" '
                /^include=.*pool[.]d\/[*][.]conf$/ {
                    print managed_include
                    replaced = 1
                    next
                }
                { print }
                END { if (! replaced) exit 42 }
            ' "\$main_configuration" > "\$temporary_directory/php-fpm.conf"
            "php-fpm\$version" -y "\$temporary_directory/php-fpm.conf" -t

            if [ -s "\$temporary_directory/pool.d/orbit-scopes.conf" ]; then
                candidate="\$pool_directory/.orbit-scopes.\$\$.candidate"
                sudo install -o root -g root -m 0644 -- \
                    "\$temporary_directory/pool.d/orbit-scopes.conf" "\$candidate"
                sudo mv -fT -- "\$candidate" "\$managed_configuration"
            else
                sudo rm -f -- "\$managed_configuration"
            fi

            sudo systemctl enable "php\$version-fpm"
            sudo systemctl reload-or-restart "php\$version-fpm"
            BASH;
    }
}
