<?php

declare(strict_types=1);

namespace App\Infrastructure\Nodes;

use App\Domain\AppDev\RuntimeConvergenceException;
use App\Infrastructure\AppDev\AppDevSshExecutor;
use App\Infrastructure\AppProd\AppProdSshExecutor;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Models\Node;
use Illuminate\Support\Collection;

final readonly class RemotePhpPackageManager
{
    private const string PHP_PACKAGE_PPA = 'ondrej/php';

    private const string PHP_PACKAGE_SOURCE_URI = 'https://ppa.launchpadcontent.net/ondrej/php/ubuntu/';

    /** @var list<string> */
    private const array SUPPORTED_UBUNTU_CODENAMES = ['noble'];

    /** @var array{preflight_step: string, discovery_error: string, source_step: string, source_error: string, install_step: string, install_error: string} */
    private const array APP_DEV_FAILURE_CONTRACT = [
        'preflight_step' => 'php-fpm-preflight',
        'discovery_error' => 'app-dev.php_fpm_discovery_failed',
        'source_step' => 'php-package-source',
        'source_error' => 'app-dev.php_package_source_unavailable',
        'install_step' => 'php-fpm-install',
        'install_error' => 'app-dev.php_install_failed',
    ];

    /** @var array{preflight_step: string, discovery_error: string, source_step: string, source_error: string, install_step: string, install_error: string} */
    private const array APP_PROD_FAILURE_CONTRACT = [
        'preflight_step' => 'app-prod-php-fpm-preflight',
        'discovery_error' => 'app-prod.php_fpm_discovery_failed',
        'source_step' => 'app-prod-php-package-source',
        'source_error' => 'app-prod.php_package_source_unavailable',
        'install_step' => 'app-prod-php-fpm-install',
        'install_error' => 'app-prod.php_install_failed',
    ];

    /** @param Collection<int, string> $versions */
    public function installForAppDev(Node $node, Collection $versions, AppDevSshExecutor $ssh): void
    {
        $this->install($node, $versions, $ssh, self::APP_DEV_FAILURE_CONTRACT);
    }

    /** @param Collection<int, string> $versions */
    public function installForAppProd(Node $node, Collection $versions, AppProdSshExecutor $ssh): void
    {
        $this->install($node, $versions, $ssh, self::APP_PROD_FAILURE_CONTRACT);
    }

    /**
     * @param Collection<int, string> $versions
     * @param array{preflight_step: string, discovery_error: string, source_step: string, source_error: string, install_step: string, install_error: string} $failure
     */
    private function install(
        Node $node,
        Collection $versions,
        AppDevSshExecutor|AppProdSshExecutor $ssh,
        array $failure,
    ): void {
        if ($versions->isEmpty()) {
            return;
        }

        $missingVersions = $this->missingVersions($node, $versions, $ssh, $failure);

        if ($missingVersions->isEmpty()) {
            return;
        }

        $versionsWithoutCandidate = $this->versionsWithoutCandidate($node, $missingVersions, $ssh, $failure);
        $codename = $versionsWithoutCandidate->isEmpty()
            ? null
            : $this->packageSourceCodename($node, $ssh, $failure);

        foreach ($missingVersions->diff($versionsWithoutCandidate) as $version) {
            $this->installVersion($node, $version, $ssh, $failure);
        }

        if (! is_string($codename)) {
            return;
        }

        $this->configurePackageSource($node, $codename, $ssh, $failure);
        $this->verifyPackageCandidates($node, $codename, $versionsWithoutCandidate, $ssh, $failure);

        foreach ($versionsWithoutCandidate as $version) {
            $this->installVersion($node, $version, $ssh, $failure);
        }
    }

    /**
     * @param Collection<int, string> $versions
     * @param array{preflight_step: string, discovery_error: string, source_step: string, source_error: string, install_step: string, install_error: string} $failure
     * @return Collection<int, string>
     */
    private function missingVersions(
        Node $node,
        Collection $versions,
        AppDevSshExecutor|AppProdSshExecutor $ssh,
        array $failure,
    ): Collection {
        $result = $ssh->execute(
            $node,
            new RemoteCommand(
                arguments: ['bash', '-seu', '--', ...$versions->all()],
                input: <<<'BASH'
                    for version in "$@"; do
                        if [ ! -x "/usr/sbin/php-fpm$version" ]; then
                            printf '%s\n' "$version"
                        fi
                    done
                    BASH,
            ),
            step: $failure['preflight_step'],
            errorCode: $failure['discovery_error'],
        );

        return $this->requestedVersionsFromOutput($versions, $result->stdout);
    }

    /**
     * @param Collection<int, string> $versions
     * @param array{preflight_step: string, discovery_error: string, source_step: string, source_error: string, install_step: string, install_error: string} $failure
     * @return Collection<int, string>
     */
    private function versionsWithoutCandidate(
        Node $node,
        Collection $versions,
        AppDevSshExecutor|AppProdSshExecutor $ssh,
        array $failure,
    ): Collection {
        $result = $ssh->execute(
            $node,
            new RemoteCommand(
                arguments: ['bash', '-seu', '--', ...$versions->all()],
                input: <<<'BASH'
                    for version in "$@"; do
                        for suffix in cli curl fpm intl mbstring sqlite3 xml zip; do
                            package="php$version-$suffix"
                            policy=$(apt-cache policy -- "$package")
                            candidate=$(printf '%s\n' "$policy" | awk '$1 == "Candidate:" { print $2; exit }')
                            if [ -z "$candidate" ] || [ "$candidate" = '(none)' ]; then
                                printf '%s\n' "$version"
                                break
                            fi
                        done
                    done
                    BASH,
            ),
            step: $failure['source_step'],
            errorCode: $failure['source_error'],
        );

        return $this->requestedVersionsFromOutput($versions, $result->stdout);
    }

    /**
     * @param AppDevSshExecutor|AppProdSshExecutor $ssh
     * @param array{preflight_step: string, discovery_error: string, source_step: string, source_error: string, install_step: string, install_error: string} $failure
     */
    private function packageSourceCodename(
        Node $node,
        AppDevSshExecutor|AppProdSshExecutor $ssh,
        array $failure,
    ): string {
        $result = $ssh->execute(
            $node,
            new RemoteCommand(
                arguments: ['bash', '-seu'],
                input: <<<'BASH'
                    if [ ! -r /etc/os-release ]; then
                        exit 1
                    fi

                    . /etc/os-release
                    printf '%s\n%s\n' "${ID:-}" "${VERSION_CODENAME:-}"
                    BASH,
            ),
            step: $failure['source_step'],
            errorCode: $failure['source_error'],
        );
        $release = preg_split('/\R/', trim($result->stdout));
        $distribution = is_array($release) ? $release[0] ?? '' : '';
        $codename = is_array($release) ? $release[1] ?? '' : '';

        if (
            ! is_array($release)
            || count($release) !== 2
            || $distribution !== 'ubuntu'
            || ! in_array($codename, self::SUPPORTED_UBUNTU_CODENAMES, strict: true)
        ) {
            throw new RuntimeConvergenceException(
                step: $failure['source_step'],
                errorCode: $failure['source_error'],
                message: 'The PHP package source is unavailable for this host.',
            );
        }

        return $codename;
    }

    /**
     * @param array{preflight_step: string, discovery_error: string, source_step: string, source_error: string, install_step: string, install_error: string} $failure
     */
    private function configurePackageSource(
        Node $node,
        string $codename,
        AppDevSshExecutor|AppProdSshExecutor $ssh,
        array $failure,
    ): void {
        $ssh->execute(
            $node,
            new RemoteCommand(
                arguments: [
                    'bash',
                    '-seu',
                    '--',
                    $codename,
                    self::PHP_PACKAGE_PPA,
                ],
                input: <<<'BASH'
                    expected_codename=$1
                    ppa=$2

                    if [ ! -r /etc/os-release ]; then
                        exit 1
                    fi

                    . /etc/os-release
                    if [ "${ID:-}" != ubuntu ] || [ "${VERSION_CODENAME:-}" != "$expected_codename" ]; then
                        exit 1
                    fi

                    sudo env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 update
                    sudo env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install \
                        --yes --no-install-recommends -- \
                        software-properties-common
                    sudo env LC_ALL=C.UTF-8 add-apt-repository --yes --no-update "ppa:$ppa"
                    sudo env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 update
                    BASH,
            ),
            step: $failure['source_step'],
            errorCode: $failure['source_error'],
        );
    }

    /**
     * @param Collection<int, string> $versions
     * @param array{preflight_step: string, discovery_error: string, source_step: string, source_error: string, install_step: string, install_error: string} $failure
     */
    private function verifyPackageCandidates(
        Node $node,
        string $codename,
        Collection $versions,
        AppDevSshExecutor|AppProdSshExecutor $ssh,
        array $failure,
    ): void {
        $ssh->execute(
            $node,
            new RemoteCommand(
                arguments: [
                    'bash',
                    '-seu',
                    '--',
                    self::PHP_PACKAGE_SOURCE_URI,
                    $codename,
                    ...$versions->all(),
                ],
                input: <<<'BASH'
                    expected_uri=$1
                    expected_codename=$2
                    shift 2
                    expected_origin="${expected_uri%/} $expected_codename/main"

                    for version in "$@"; do
                        for suffix in cli curl fpm intl mbstring sqlite3 xml zip; do
                            package="php$version-$suffix"
                            policy=$(apt-cache policy -- "$package")
                            candidate=$(printf '%s\n' "$policy" | awk '$1 == "Candidate:" { print $2; exit }')
                            if [ -z "$candidate" ] || [ "$candidate" = '(none)' ]; then
                                exit 1
                            fi

                            apt-cache madison -- "$package" | awk -F '|' -v candidate="$candidate" -v origin="$expected_origin" '
                                function trim(value) {
                                    gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
                                    return value
                                }
                                trim($2) == candidate && index(trim($3), origin " ") == 1 { found = 1 }
                                END { exit found ? 0 : 1 }
                            '
                        done
                    done
                    BASH,
            ),
            step: $failure['source_step'],
            errorCode: $failure['source_error'],
        );
    }

    /**
     * @param array{preflight_step: string, discovery_error: string, source_step: string, source_error: string, install_step: string, install_error: string} $failure
     */
    private function installVersion(
        Node $node,
        string $version,
        AppDevSshExecutor|AppProdSshExecutor $ssh,
        array $failure,
    ): void {
        $ssh->execute(
            $node,
            new RemoteCommand(
                arguments: ['bash', '-seu', '--', $version],
                input: <<<'BASH'
                    version=$1

                    if [ -x "/usr/sbin/php-fpm$version" ]; then
                        exit 0
                    fi

                    sudo env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install \
                        --yes --no-install-recommends -- \
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
            step: $failure['install_step'],
            errorCode: $failure['install_error'],
        );
    }

    /**
     * @param Collection<int, string> $requestedVersions
     * @return Collection<int, string>
     */
    private function requestedVersionsFromOutput(Collection $requestedVersions, string $output): Collection
    {
        $versions = preg_split('/\R/', trim($output));

        return $requestedVersions
            ->intersect(is_array($versions) ? $versions : [])
            ->values();
    }
}
