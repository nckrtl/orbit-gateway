<?php

declare(strict_types=1);

namespace App\Infrastructure\MacOs;

use App\Domain\AppDev\AppDevCertificateManager;
use App\Domain\AppDev\AppDevHostPaths;
use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\Certificates\LeafCertificateSigner;
use App\Domain\Nodes\RoleName;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshExecutor;
use App\Models\Instance;
use App\Models\Node;
use App\Models\Workspace;

/** @mago-expect lint:excessive-parameter-list Explicit trust and transport dependencies keep certificate mutation bounded. */
final readonly class MacOsAppDevCertificateManager implements AppDevCertificateManager
{
    public function __construct(
        private AppDevHostPaths $paths,
        private MacOsFilesystemLayout $layout,
        private MacOsSshConnectionFactory $connections,
        private SshExecutor $ssh,
        private MacOsSteadyStateCommandGuard $guard,
        private LeafCertificateSigner $signer,
    ) {}

    public function convergeInstance(Instance $instance): void
    {
        $instance->loadMissing(['app', 'node']);
        $expected = $this->paths->instanceCheckout(
            $instance->node,
            RoleName::AppDev,
            $instance->app->slug,
            $instance->name,
        );

        if ($instance->checkout_path !== $expected) {
            throw new \App\Domain\Shared\ResourceOperationException(
                errorCode: 'instance.path_invalid',
                message: 'The stored Darwin instance checkout path is not managed by Orbit.',
            );
        }

        $this->converge($instance->node, "instance-{$instance->id}", $instance->hostname);
    }

    public function removeInstance(Instance $instance): void
    {
        $instance->loadMissing('node');
        $this->remove($instance->node, "instance-{$instance->id}");
    }

    public function convergeWorkspace(Workspace $workspace): void
    {
        $workspace->loadMissing(['instance.app', 'instance.node']);
        $expected = $this->paths->workspaceCheckout(
            $workspace->instance->node,
            $workspace->instance->app->slug,
            $workspace->name,
        );

        if ($workspace->checkout_path !== $expected) {
            throw new \App\Domain\Shared\ResourceOperationException(
                errorCode: 'workspace.path_unsupported',
                message: 'Darwin workspaces must use the managed Orbit worktree path.',
            );
        }

        $this->converge(
            $workspace->instance->node,
            "workspace-{$workspace->id}",
            $workspace->hostname,
        );
    }

    public function removeWorkspace(Workspace $workspace): void
    {
        $workspace->loadMissing('instance.node');
        $this->remove($workspace->instance->node, "workspace-{$workspace->id}");
    }

    private function converge(Node $node, string $scope, string $hostname): void
    {
        $home = $this->paths->home($node, RoleName::AppDev);
        $root = dirname($this->layout->certificateCurrent($home, $scope));
        $version = bin2hex(random_bytes(12));
        $candidate = "{$root}/versions/{$version}.candidate";
        $rootCertificate = $this->signer->rootCertificate();
        $rootHash = hash('sha256', $rootCertificate);
        $request = $this->execute(
            $node,
            new RemoteCommand(
                arguments: [
                    '/bin/bash',
                    '-seu',
                    '--',
                    $root,
                    $candidate,
                    $hostname,
                    $this->opensslPath($node),
                    $rootHash,
                    $home,
                ],
                input: <<<'BASH'
                    root=$1
                    candidate=$2
                    hostname=$3
                    openssl=$4
                    expected_root_hash=$5
                    home=$6
                    current="$root/current"
                    orbit_root="$home/.orbit"
                    certificates_root="$orbit_root/certificates"
                    versions_root="$root/versions"
                    validity_seconds=0
                    certificate_extension() {
                        "$openssl" x509 -in "$1" -noout -ext "$2" 2>/dev/null \
                            | tr '\n' ' ' | tr -s ' ' | sed 's/^ //; s/ $//'
                    }
                    test -d "$home"
                    test ! -L "$home"
                    test "$(cd "$home" && pwd -P)" = "$home"
                    for managed_directory in "$orbit_root" "$certificates_root" "$root" "$versions_root"; do
                        if [ -L "$managed_directory" ]; then exit 1; fi
                        if [ -e "$managed_directory" ]; then
                            test -d "$managed_directory"
                        else
                            mkdir -- "$managed_directory"
                            chmod 0700 "$managed_directory"
                        fi
                        test ! -L "$managed_directory"
                        test "$(cd "$managed_directory" && pwd -P)" = "$managed_directory"
                    done

                    if [ -e "$current" ] || [ -L "$current" ]; then
                        test -L "$current"
                        target=$(readlink "$current")
                        target_valid=0
                        case "$target" in
                            "$root/versions/"*) ;;
                            *) exit 1 ;;
                        esac
                        if [ -d "$target" ] && [ ! -L "$target" ] && \
                            [ "$(cd "$target" && pwd -P)" = "$target" ] && \
                            [ -f "$target/key.pem" ] && [ ! -L "$target/key.pem" ] && \
                            [ -f "$target/cert.pem" ] && [ ! -L "$target/cert.pem" ] && \
                            [ -f "$target/root.pem" ] && [ ! -L "$target/root.pem" ]; then
                            target_valid=1
                            not_before=$("$openssl" x509 -in "$target/cert.pem" -noout -startdate | cut -d= -f2-)
                            not_after=$("$openssl" x509 -in "$target/cert.pem" -noout -enddate | cut -d= -f2-)
                            if not_before_epoch=$(/bin/date -j -u -f '%b %e %T %Y %Z' "$not_before" +%s 2>/dev/null) && \
                                not_after_epoch=$(/bin/date -j -u -f '%b %e %T %Y %Z' "$not_after" +%s 2>/dev/null); then
                                validity_seconds=$((not_after_epoch - not_before_epoch))
                            fi
                        fi
                        if [ "$target_valid" -eq 1 ] \
                            && [ -f "$target/key.pem" ] && [ -f "$target/cert.pem" ] && [ -f "$target/root.pem" ] \
                            && [ "$(/usr/bin/shasum -a 256 "$target/root.pem" | cut -d ' ' -f 1)" = "$expected_root_hash" ] \
                            && "$openssl" verify -CAfile "$target/root.pem" "$target/cert.pem" >/dev/null \
                            && "$openssl" x509 -in "$target/cert.pem" -noout -checkend 2592000 >/dev/null \
                            && [ "$validity_seconds" -ge 34214400 ] && [ "$validity_seconds" -le 34300800 ] \
                            && "$openssl" x509 -in "$target/cert.pem" -noout -checkhost "$hostname" >/dev/null \
                            && "$openssl" pkey -in "$target/key.pem" -text_pub -noout 2>/dev/null | grep -qx 'ED25519 Public-Key:' \
                            && [ "$(certificate_extension "$target/cert.pem" basicConstraints)" = 'X509v3 Basic Constraints: critical CA:FALSE' ] \
                            && [ "$(certificate_extension "$target/cert.pem" keyUsage)" = 'X509v3 Key Usage: critical Digital Signature' ] \
                            && [ "$(certificate_extension "$target/cert.pem" extendedKeyUsage)" = 'X509v3 Extended Key Usage: TLS Web Server Authentication' ] \
                            && [ "$(certificate_extension "$target/cert.pem" subjectAltName)" = "X509v3 Subject Alternative Name: DNS:$hostname" ] \
                            && test "$("$openssl" pkey -in "$target/key.pem" -pubout 2>/dev/null)" = \
                                "$("$openssl" x509 -in "$target/cert.pem" -pubkey -noout 2>/dev/null)"; then
                            printf 'ORBIT_CERTIFICATE_CURRENT\n'
                            exit 0
                        fi
                    fi

                    if [ -e "$candidate" ] || [ -L "$candidate" ]; then exit 1; fi
                    mkdir -m 0700 -- "$candidate"
                    "$openssl" genpkey -algorithm ED25519 -out "$candidate/key.pem"
                    chmod 0600 "$candidate/key.pem"
                    "$openssl" req -new -key "$candidate/key.pem" -out "$candidate/request.pem" -subj "/CN=$hostname"
                    chmod 0644 "$candidate/request.pem"
                    cat "$candidate/request.pem"
                    BASH,
            ),
            step: 'certificate-request',
            errorCode: 'app-dev.certificate_request_failed',
        );

        if (trim($request) === 'ORBIT_CERTIFICATE_CURRENT') {
            return;
        }

        $certificate = $this->signer->sign($hostname, $request);
        $published = "{$root}/versions/{$version}";
        $certificateEncoded = base64_encode($certificate);
        $rootEncoded = base64_encode($rootCertificate);
        $this->execute(
            $node,
            new RemoteCommand(
                arguments: [
                    '/bin/bash',
                    '-seu',
                    '--',
                    $root,
                    $candidate,
                    $published,
                    $hostname,
                    $this->opensslPath($node),
                    $home,
                ],
                input: <<<BASH
                    root=\$1
                    candidate=\$2
                    published=\$3
                    hostname=\$4
                    openssl=\$5
                    home=\$6
                    orbit_root="\$home/.orbit"
                    certificates_root="\$orbit_root/certificates"
                    versions_root="\$root/versions"
                    temporary_link="\$root/.current-{$version}"
                    test -d "\$home"
                    test ! -L "\$home"
                    test "\$(cd "\$home" && pwd -P)" = "\$home"
                    for managed_directory in "\$orbit_root" "\$certificates_root" "\$root" "\$versions_root" "\$candidate"; do
                        if [ -L "\$managed_directory" ]; then exit 1; fi
                        test -d "\$managed_directory"
                        test "\$(cd "\$managed_directory" && pwd -P)" = "\$managed_directory"
                    done
                    test ! -e "\$published"; test ! -L "\$published"
                    test ! -e "\$temporary_link"; test ! -L "\$temporary_link"
                    printf '%s' '{$certificateEncoded}' | /usr/bin/base64 --decode > "\$candidate/cert.pem"
                    printf '%s' '{$rootEncoded}' | /usr/bin/base64 --decode > "\$candidate/root.pem"
                    chmod 0644 "\$candidate/cert.pem" "\$candidate/root.pem"
                    certificate_extension() {
                        "\$openssl" x509 -in "\$candidate/cert.pem" -noout -ext "\$1" 2>/dev/null | tr '\n' ' ' | tr -s ' ' | sed 's/^ //; s/ $//'
                    }
                    "\$openssl" pkey -in "\$candidate/key.pem" -text_pub -noout 2>/dev/null | grep -qx 'ED25519 Public-Key:'
                    "\$openssl" verify -CAfile "\$candidate/root.pem" "\$candidate/cert.pem"
                    "\$openssl" x509 -in "\$candidate/cert.pem" -noout -checkhost "\$hostname"
                    test "\$(certificate_extension basicConstraints)" = 'X509v3 Basic Constraints: critical CA:FALSE'
                    test "\$(certificate_extension keyUsage)" = 'X509v3 Key Usage: critical Digital Signature'
                    test "\$(certificate_extension extendedKeyUsage)" = 'X509v3 Extended Key Usage: TLS Web Server Authentication'
                    test "\$(certificate_extension subjectAltName)" = "X509v3 Subject Alternative Name: DNS:\$hostname"
                    test "\$("\$openssl" pkey -in "\$candidate/key.pem" -pubout 2>/dev/null)" = \
                        "\$("\$openssl" x509 -in "\$candidate/cert.pem" -pubkey -noout 2>/dev/null)"
                    mv -- "\$candidate" "\$published"
                    ln -s -- "\$published" "\$temporary_link"
                    mv -h -f -- "\$temporary_link" "\$root/current"
                    BASH,
            ),
            step: 'certificate-publish',
            errorCode: 'app-dev.certificate_publish_failed',
        );
    }

    private function remove(Node $node, string $scope): void
    {
        $home = $this->paths->home($node, RoleName::AppDev);
        $root = dirname($this->layout->certificateCurrent($home, $scope));
        $this->execute(
            $node,
            new RemoteCommand(
                arguments: ['/bin/bash', '-seu', '--', $root, $home],
                input: <<<'BASH'
                    root=$1
                    home=$2
                    orbit_root="$home/.orbit"
                    certificates_root="$orbit_root/certificates"
                    case "$root" in
                        "$home/.orbit/certificates/instance-"*|"$home/.orbit/certificates/workspace-"*) ;;
                        *) exit 1 ;;
                    esac
                    test -d "$home"
                    test ! -L "$home"
                    test "$(cd "$home" && pwd -P)" = "$home"
                    for managed_directory in "$orbit_root" "$certificates_root" "$root"; do
                        if [ ! -e "$managed_directory" ] && [ ! -L "$managed_directory" ]; then exit 0; fi
                        test -d "$managed_directory"
                        test ! -L "$managed_directory"
                        test "$(cd "$managed_directory" && pwd -P)" = "$managed_directory"
                    done
                    find -P "$root" -depth -delete
                    BASH,
            ),
            step: 'certificate-remove',
            errorCode: 'app-dev.certificate_remove_failed',
        );
    }

    private function execute(Node $node, RemoteCommand $command, string $step, string $errorCode): string
    {
        $connection = $this->connections->make($node);
        $result = $this->ssh->execute($connection, $this->guard->guard($command));

        if (! $result->succeeded()) {
            throw new RuntimeConvergenceException(
                step: $step,
                errorCode: $errorCode,
                message: 'The macOS certificate operation failed.',
                result: $result,
            );
        }

        return $result->stdout;
    }

    private function opensslPath(Node $node): string
    {
        $prefix = match ($node->architecture) {
            'arm64' => '/opt/homebrew',
            'x86_64' => '/usr/local',
            default => throw new \App\Domain\Shared\ResourceOperationException(
                errorCode: 'instance.platform_unsupported',
                message: 'The Darwin architecture is not supported.',
            ),
        };

        return "{$prefix}/opt/openssl@3/bin/openssl";
    }
}
