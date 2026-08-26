<?php

declare(strict_types=1);

namespace App\Infrastructure\Nodes;

use App\Domain\Nodes\RoleName;
use App\Infrastructure\AppDev\AppDevSshExecutor;
use App\Infrastructure\AppProd\AppProdSshExecutor;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Models\Node;
use Illuminate\Support\Collection;

final readonly class RemotePhpPackageManager
{
    private const string EXPECTED_DISTRIBUTION = 'ubuntu';

    private const string EXPECTED_CODENAME = 'resolute';

    private const string SOURCE_URI = 'https://packages.sury.org/php/';

    private const string KEY_URL = 'https://packages.sury.org/php/apt.gpg';

    private const string KEYRING_PATH = '/usr/share/keyrings/orbit-sury-php.gpg';

    private const string SOURCE_PATH = '/etc/apt/sources.list.d/orbit-php.sources';

    private const string KEY_SHA256 = 'b486fd5488185c4c46467960fa69c53d5085fec492cf76b9eaf3db33561c9d7c';

    private const string PRIMARY_FINGERPRINT = '15058500A0235D97F5D10063B188E2B695BD4743';

    private const string SECONDARY_FINGERPRINT = '45BEA3E529112086C622F8A4B214EAC28059B8AC';

    private const string RESOLUTE_SIGNER = self::PRIMARY_FINGERPRINT;

    /** @var list<string> */
    private const array COMMON_SUFFIXES = [
        'cli',
        'fpm',
        'common',
        'bcmath',
        'curl',
        'gd',
        'imagick',
        'intl',
        'mbstring',
        'mysql',
        'pgsql',
        'redis',
        'sqlite3',
        'xml',
        'zip',
    ];

    /** @var array{source_step: string, source_error: string, install_step: string, install_error: string} */
    private const array APP_DEV_FAILURE_CONTRACT = [
        'source_step' => 'php-package-source',
        'source_error' => 'app-dev.php_package_source_unavailable',
        'install_step' => 'php-fpm-install',
        'install_error' => 'app-dev.php_install_failed',
    ];

    /** @var array{source_step: string, source_error: string, install_step: string, install_error: string} */
    private const array APP_PROD_FAILURE_CONTRACT = [
        'source_step' => 'app-prod-php-package-source',
        'source_error' => 'app-prod.php_package_source_unavailable',
        'install_step' => 'app-prod-php-fpm-install',
        'install_error' => 'app-prod.php_install_failed',
    ];

    /** @param Collection<int, string> $versions */
    public function installForAppDev(Node $node, Collection $versions, AppDevSshExecutor $ssh): void
    {
        $this->install($node, $versions, $ssh, self::APP_DEV_FAILURE_CONTRACT, profile: 'app-dev');
    }

    /** @param Collection<int, string> $versions */
    public function installForAppProd(Node $node, Collection $versions, AppProdSshExecutor $ssh): void
    {
        $needsPcov = $node->roles->pluck('role')->contains(RoleName::AppDev);

        $profile = $needsPcov ? 'app-dev' : 'app-prod';

        $this->install($node, $versions, $ssh, self::APP_PROD_FAILURE_CONTRACT, $profile);
    }

    /**
     * @param Collection<int, string> $versions
     * @param array{source_step: string, source_error: string, install_step: string, install_error: string} $failure
     */
    private function install(
        Node $node,
        Collection $versions,
        AppDevSshExecutor|AppProdSshExecutor $ssh,
        array $failure,
        string $profile,
    ): void {
        if ($versions->isEmpty()) {
            return;
        }

        /** @var array<string, list<string>> $profiles */
        $profiles = [];

        foreach ($versions as $version) {
            $profiles[$version] = $this->packages($version, $profile);
        }

        $allPackages = array_values(array_unique(array_merge(...array_values($profiles))));

        $this->convergeSource($node, $allPackages, $ssh, $failure);

        foreach ($profiles as $version => $packages) {
            $this->installProfile(
                $node,
                $version,
                $profile,
                $packages,
                $ssh,
                $failure,
            );
        }
    }

    /**
     * @param list<string> $packages
     * @param array{source_step: string, source_error: string, install_step: string, install_error: string} $failure
     */
    private function convergeSource(
        Node $node,
        array $packages,
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
                    self::EXPECTED_DISTRIBUTION,
                    self::EXPECTED_CODENAME,
                    self::SOURCE_URI,
                    self::KEY_URL,
                    self::KEYRING_PATH,
                    self::SOURCE_PATH,
                    self::KEY_SHA256,
                    self::PRIMARY_FINGERPRINT,
                    self::SECONDARY_FINGERPRINT,
                    self::RESOLUTE_SIGNER,
                    ...$packages,
                ],
                input: <<<'BASH'
                    expected_id=$1
                    expected_codename=$2
                    expected_uri=$3
                    key_url=$4
                    keyring_path=$5
                    source_path=$6
                    expected_sha256=$7
                    primary_fingerprint=$8
                    secondary_fingerprint=$9
                    resolute_signer=${10}
                    shift 10

                    fail_os() {
                        printf '%s\n' 'Orbit requires Ubuntu 26.04 Resolute.' >&2
                        exit 1
                    }

                    if [ ! -r /etc/os-release ]; then
                        fail_os
                    fi

                    if ! . /etc/os-release; then
                        fail_os
                    fi

                    if [ "${ID:-}" != "$expected_id" ] || [ "${VERSION_CODENAME:-}" != "$expected_codename" ]; then
                        fail_os
                    fi

                    for configured_source in \
                        /etc/apt/sources.list \
                        /etc/apt/sources.list.d/*.list \
                        /etc/apt/sources.list.d/*.sources
                    do
                        if [ ! -f "$configured_source" ] || [ "$configured_source" = "$source_path" ]; then
                            continue
                        fi

                        if sudo grep -Eiq \
                            'ppa\.launchpadcontent\.net/ondrej/php|packages\.sury\.org/php|ondrej/php' \
                            -- "$configured_source"
                        then
                            printf '%s\n' 'A conflicting PHP package source is configured.' >&2
                            exit 1
                        fi
                    done

                    for managed_path in "$keyring_path" "$source_path"; do
                        if [ ! -e "$managed_path" ] && [ ! -L "$managed_path" ]; then
                            continue
                        fi

                        if [ -L "$managed_path" ] \
                            || [ ! -f "$managed_path" ] \
                            || [ "$(stat -c '%U:%G' -- "$managed_path")" != root:root ] \
                            || [ "$(stat -c '%a' -- "$managed_path")" != 644 ]
                        then
                            printf '%s\n' 'An Orbit PHP package source file has unsafe ownership or mode.' >&2
                            exit 1
                        fi
                    done

                    umask 077
                    work_directory=$(mktemp -d)
                    gnupg_home="$work_directory/gnupg"
                    install -d -m 0700 -- "$gnupg_home"
                    downloaded_key="$work_directory/apt.gpg"
                    source_candidate="$work_directory/orbit-php.sources"
                    key_backup="$work_directory/keyring.backup"
                    source_backup="$work_directory/source.backup"
                    had_key=0
                    had_source=0
                    published=0

                    if [ -f "$keyring_path" ]; then
                        cp -- "$keyring_path" "$key_backup"
                        had_key=1
                    fi

                    if [ -f "$source_path" ]; then
                        cp -- "$source_path" "$source_backup"
                        had_source=1
                    fi

                    restore_source() {
                        status=$?
                        trap - EXIT

                        if [ "$status" -ne 0 ] && [ "$published" -eq 1 ]; then
                            if [ "$had_key" -eq 1 ]; then
                                sudo install -m 0644 -o root -g root -- "$key_backup" "$keyring_path"
                            else
                                sudo rm -f -- "$keyring_path"
                            fi

                            if [ "$had_source" -eq 1 ]; then
                                sudo install -m 0644 -o root -g root -- "$source_backup" "$source_path"
                            else
                                sudo rm -f -- "$source_path"
                            fi
                        fi

                        rm -rf -- "$work_directory"
                        exit "$status"
                    }
                    trap restore_source EXIT

                    curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
                        --output "$downloaded_key" \
                        "$key_url"
                    printf '%s  %s\n' "$expected_sha256" "$downloaded_key" | sha256sum --check --status

                    actual_fingerprints=$(GNUPGHOME="$gnupg_home" gpg --batch --with-colons --show-keys "$downloaded_key" \
                        | awk -F: '$1 == "fpr" { print $10 }' \
                        | sort -u)
                    expected_fingerprints=$(printf '%s\n%s\n' \
                        "$primary_fingerprint" \
                        "$secondary_fingerprint" \
                        | sort -u)
                    if [ "$actual_fingerprints" != "$expected_fingerprints" ] \
                        || ! printf '%s\n' "$actual_fingerprints" | grep -qxF "$resolute_signer"
                    then
                        printf '%s\n' 'The Sury PHP signing key identity does not match Orbit pins.' >&2
                        exit 1
                    fi

                    printf 'Types: deb\nURIs: %s\nSuites: %s\nComponents: main\nSigned-By: %s\n' \
                        "$expected_uri" \
                        "$expected_codename" \
                        "$keyring_path" \
                        > "$source_candidate"

                    if [ ! -f "$keyring_path" ] || ! cmp -s -- "$downloaded_key" "$keyring_path"; then
                        keyring_candidate=$(sudo mktemp "${keyring_path}.orbit.XXXXXX")
                        sudo install -m 0644 -o root -g root -- "$downloaded_key" "$keyring_candidate"
                        published=1
                        sudo mv -- "$keyring_candidate" "$keyring_path"
                    fi

                    if [ ! -f "$source_path" ] || ! cmp -s -- "$source_candidate" "$source_path"; then
                        apt_source_candidate=$(sudo mktemp "${source_path}.orbit.XXXXXX")
                        sudo install -m 0644 -o root -g root -- "$source_candidate" "$apt_source_candidate"
                        published=1
                        sudo mv -- "$apt_source_candidate" "$source_path"
                    fi

                    sudo env DEBIAN_FRONTEND=noninteractive \
                        apt-get -o DPkg::Lock::Timeout=300 update

                    expected_origin="${expected_uri%/} $expected_codename/main"
                    for package in "$@"; do
                        policy=$(apt-cache policy -- "$package")
                        candidate=$(printf '%s\n' "$policy" | awk '$1 == "Candidate:" { print $2; exit }')
                        if [ -z "$candidate" ] || [ "$candidate" = '(none)' ]; then
                            printf '%s\n' "A required PHP package candidate is unavailable: $package" >&2
                            exit 1
                        fi

                        apt-cache madison -- "$package" | awk -F '|' \
                            -v candidate="$candidate" \
                            -v origin="$expected_origin" '
                                function trim(value) {
                                    gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
                                    return value
                                }
                                trim($2) == candidate && index(trim($3), origin " ") == 1 { found = 1 }
                                END { exit found ? 0 : 1 }
                            '
                    done

                    published=0
                    trap - EXIT
                    rm -rf -- "$work_directory"
                    BASH,
            ),
            step: $failure['source_step'],
            errorCode: $failure['source_error'],
        );
    }

    /**
     * @param list<string> $packages
     * @param array{source_step: string, source_error: string, install_step: string, install_error: string} $failure
     * @mago-expect lint:excessive-parameter-list The executor and stable failure contract stay explicit at this remote boundary.
     */
    private function installProfile(
        Node $node,
        string $version,
        string $profile,
        array $packages,
        AppDevSshExecutor|AppProdSshExecutor $ssh,
        array $failure,
    ): void {
        $pcovSetup = $profile === 'app-dev'
            ? <<<'BASH'
                sudo phpenmod -v "$version" -s cli pcov
                sudo phpdismod -v "$version" -s fpm pcov
                BASH
            : '';
        $pcovVerification = $profile === 'app-dev'
            ? <<<'BASH'
                printf '%s\n' "$cli_modules" | grep -qxF pcov
                BASH
            : <<<'BASH'
                if printf '%s\n' "$cli_modules" | grep -qxF pcov; then
                    exit 1
                fi
                BASH;

        $ssh->execute(
            $node,
            new RemoteCommand(
                arguments: ['bash', '-seu', '--', $version, $profile, ...$packages],
                input: <<<'BASH'
                    expected_id=ubuntu
                    expected_codename=resolute
                    version=$1
                    profile=$2
                    shift 2

                    if [ ! -r /etc/os-release ]; then
                        printf '%s\n' 'Orbit requires Ubuntu 26.04 Resolute.' >&2
                        exit 1
                    fi

                    if ! . /etc/os-release; then
                        printf '%s\n' 'Orbit requires Ubuntu 26.04 Resolute.' >&2
                        exit 1
                    fi

                    if [ "${ID:-}" != "$expected_id" ] || [ "${VERSION_CODENAME:-}" != "$expected_codename" ]; then
                        printf '%s\n' 'Orbit requires Ubuntu 26.04 Resolute.' >&2
                        exit 1
                    fi

                    missing_packages=()
                    for package in "$@"; do
                        case "$package" in
                            "php$version-"*) ;;
                            *) exit 1 ;;
                        esac

                        if ! dpkg-query -W -f='${Status}' -- "$package" 2>/dev/null \
                            | grep -qxF 'install ok installed'
                        then
                            missing_packages+=("$package")
                        fi
                    done

                    if [ "${#missing_packages[@]}" -gt 0 ]; then
                        sudo env DEBIAN_FRONTEND=noninteractive \
                            apt-get -o DPkg::Lock::Timeout=300 install \
                            --yes --no-install-recommends -- \
                            "${missing_packages[@]}"
                    fi

                    for package in "$@"; do
                        dpkg-query -W -f='${Status}' -- "$package" \
                            | grep -qxF 'install ok installed'
                    done
                    BASH."\n".$pcovSetup."\n".<<<'BASH'
                    sudo systemctl enable --now "php$version-fpm.service"

                    php"$version" -v >/dev/null
                    php-fpm"$version" -v >/dev/null
                    cli_modules=$(php"$version" -m | tr '[:upper:]' '[:lower:]')
                    fpm_modules=$(php-fpm"$version" -m | tr '[:upper:]' '[:lower:]')
                    for module in bcmath curl gd imagick intl mbstring mysqli pdo_mysql pdo_pgsql redis pdo_sqlite simplexml xml zip; do
                        printf '%s\n' "$cli_modules" | grep -qxF "$module"
                        printf '%s\n' "$fpm_modules" | grep -qxF "$module"
                    done
                    BASH."\n".$pcovVerification."\n".<<<'BASH'
                    if printf '%s\n' "$fpm_modules" | grep -qxF pcov; then
                        exit 1
                    fi

                    sudo systemctl is-enabled --quiet "php$version-fpm.service"
                    sudo systemctl is-active --quiet "php$version-fpm.service"
                    BASH,
            ),
            step: $failure['install_step'],
            errorCode: $failure['install_error'],
        );
    }

    /** @return list<string> */
    private function packages(string $version, string $profile): array
    {
        $suffixes = self::COMMON_SUFFIXES;

        if ($version === '8.4') {
            $suffixes[] = 'opcache';
        }

        if ($profile === 'app-dev') {
            $suffixes[] = 'pcov';
        }

        return array_map(
            static fn (string $suffix): string => "php{$version}-{$suffix}",
            $suffixes,
        );
    }
}
