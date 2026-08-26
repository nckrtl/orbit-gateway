<?php

declare(strict_types=1);

namespace App\Infrastructure\AppDev;

use App\Domain\AppDev\AppDevPhpFpmManager;
use App\Infrastructure\Nodes\RemotePhpPackageManager;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Models\Node;
use App\Rules\SupportedPhpVersion;
use Illuminate\Support\Collection;

/** @mago-expect lint:excessive-parameter-list Fixed paths preserve isolated publication tests; the package service owns host installation. */
final readonly class RemoteAppDevPhpFpmManager implements AppDevPhpFpmManager
{
    public function __construct(
        private AppDevSiteRepository $sites,
        private AppDevPhpFpmConfigRenderer $renderer,
        private AppDevSshExecutor $ssh,
        private string $phpRoot = '/etc/php',
        private string $lockDirectory = '/run/lock',
        private RemotePhpPackageManager $packages = new RemotePhpPackageManager,
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
        $this->packages->installForAppDev($node, $desiredVersions, $this->ssh);

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
                arguments: ['bash', '-seu', '--', $this->phpRoot],
                input: <<<'BASH'
                    php_root=$1
                    for path in "$php_root"/*/fpm/pool.d/orbit-scopes.conf; do
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

    private function publishVersion(Node $node, string $version, string $configuration): void
    {
        $this->ssh->execute(
            $node,
            new RemoteCommand(
                arguments: [
                    'sudo',
                    'bash',
                    '-seu',
                    '--',
                    $version,
                    $this->phpRoot,
                    $this->lockDirectory,
                ],
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
            php_root=\$2
            lock_directory=\$3
            pool_directory="\$php_root/\$version/fpm/pool.d"
            main_configuration="\$php_root/\$version/fpm/php-fpm.conf"
            managed_configuration="\$pool_directory/orbit-scopes.conf"
            exec 9>"\$lock_directory/orbit-php-fpm-\$version.lock"
            flock -w 30 9
            temporary_directory=\$(mktemp -d)
            candidate="\$temporary_directory/orbit-scopes.conf"
            backup="\$temporary_directory/orbit-scopes.backup"
            trap 'rm -rf -- "\$temporary_directory"' EXIT
            install -d -m 0755 -- "\$temporary_directory/pool.d"

            for pool in "\$pool_directory"/*.conf; do
                if [ ! -e "\$pool" ] || [ "\$pool" = "\$managed_configuration" ]; then
                    continue
                fi

                cp -- "\$pool" "\$temporary_directory/pool.d/"
            done

            printf '%s' '{$encoded}' | base64 --decode > "\$candidate"
            cp -- "\$candidate" "\$temporary_directory/pool.d/orbit-scopes.conf"
            awk -v managed_include="include=\$temporary_directory/pool.d/*.conf" '
                /^include=.*pool[.]d\/[*][.]conf$/ {
                    print managed_include
                    replaced = 1
                    next
                }
                { print }
                END { if (! replaced) exit 42 }
            ' "\$main_configuration" > "\$temporary_directory/php-fpm.conf"
            sudo "php-fpm\$version" -y "\$temporary_directory/php-fpm.conf" -t

            if [ -f "\$managed_configuration" ] && cmp -s -- "\$candidate" "\$managed_configuration"; then
                exit 0
            fi

            had_previous=0
            if [ -f "\$managed_configuration" ]; then
                sudo cp -a -- "\$managed_configuration" "\$backup"
                had_previous=1
            fi

            if [ -s "\$candidate" ]; then
                staged="\$pool_directory/.orbit-scopes.\$\$.candidate"
                sudo install -o root -g root -m 0644 -- "\$candidate" "\$staged"
                sudo mv -fT -- "\$staged" "\$managed_configuration"
            else
                sudo rm -f -- "\$managed_configuration"
            fi

            if ! sudo systemctl enable "php\$version-fpm" || ! sudo systemctl reload-or-restart "php\$version-fpm"; then
                if [ "\$had_previous" = 1 ]; then
                    rollback="\$pool_directory/.orbit-scopes.\$\$.rollback"
                    sudo cp -a -- "\$backup" "\$rollback"
                    sudo mv -fT -- "\$rollback" "\$managed_configuration"
                else
                    sudo rm -f -- "\$managed_configuration"
                fi
                sudo systemctl reload-or-restart "php\$version-fpm" || true
                exit 1
            fi
            BASH;
    }
}
