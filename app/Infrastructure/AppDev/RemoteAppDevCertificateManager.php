<?php

declare(strict_types=1);

namespace App\Infrastructure\AppDev;

use App\Domain\AppDev\AppDevCertificateManager;
use App\Domain\Certificates\LeafCertificateSigner;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Models\Instance;
use App\Models\Node;
use App\Models\Workspace;

final readonly class RemoteAppDevCertificateManager implements AppDevCertificateManager
{
    public function __construct(
        private AppDevSshExecutor $ssh,
        private LeafCertificateSigner $signer,
    ) {}

    public function convergeInstance(Instance $instance): void
    {
        $instance->loadMissing('node');
        $this->converge($instance->node, "instance-{$instance->id}", $instance->hostname);
    }

    public function removeInstance(Instance $instance): void
    {
        $instance->loadMissing('node');
        $this->remove($instance->node, "instance-{$instance->id}");
    }

    public function convergeWorkspace(Workspace $workspace): void
    {
        $workspace->loadMissing('instance.node');
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
        $version = bin2hex(random_bytes(8));
        $rootCertificate = $this->signer->rootCertificate();
        $rootHash = hash('sha256', $rootCertificate);
        $request = $this->ssh->execute(
            $node,
            new RemoteCommand(
                arguments: ['bash', '-seu', '--', $scope, $hostname, $version, $rootHash],
                input: <<<'BASH'
                    scope=$1
                    hostname=$2
                    version=$3
                    expected_root_hash=$4
                    root="/home/orbit/.orbit/certificates/$scope"
                    current="$root/current"
                    caddy_current="/etc/caddy/orbit-certificates/$scope/current"

                    if [ -f "$current/key.pem" ] && [ -f "$current/cert.pem" ] && [ -f "$current/root.pem" ] && \
                        sudo test -f "$caddy_current/key.pem" && sudo test -f "$caddy_current/cert.pem" && \
                        [ "$(sha256sum "$current/root.pem" | cut -d ' ' -f 1)" = "$expected_root_hash" ] && \
                        openssl verify -CAfile "$current/root.pem" "$current/cert.pem" >/dev/null && \
                        openssl x509 -in "$current/cert.pem" -noout -checkend 86400 >/dev/null && \
                        openssl x509 -in "$current/cert.pem" -noout -checkhost "$hostname" >/dev/null && \
                        [ "$(openssl pkey -in "$current/key.pem" -pubout 2>/dev/null)" = \
                            "$(openssl x509 -in "$current/cert.pem" -pubkey -noout 2>/dev/null)" ] && \
                        [ "$(openssl x509 -in "$current/cert.pem" -fingerprint -sha256 -noout)" = \
                            "$(sudo openssl x509 -in "$caddy_current/cert.pem" -fingerprint -sha256 -noout)" ] && \
                        [ "$(sudo openssl pkey -in "$caddy_current/key.pem" -pubout 2>/dev/null)" = \
                            "$(sudo openssl x509 -in "$caddy_current/cert.pem" -pubkey -noout 2>/dev/null)" ]; then
                        printf 'CURRENT\n'
                        exit 0
                    fi

                    install -d -m 0700 -- "$root/versions"
                    find "$root/versions" -mindepth 1 -maxdepth 1 -type d -name '*.candidate' -exec rm -rf -- {} +
                    candidate="$root/versions/$version.candidate"
                    install -d -m 0700 -- "$candidate"
                    openssl genpkey -algorithm ED25519 -out "$candidate/key.pem"
                    chmod 0600 "$candidate/key.pem"
                    openssl req -new -key "$candidate/key.pem" -subj "/CN=$hostname" -out "$candidate/request.pem"
                    cat "$candidate/request.pem"
                    BASH,
            ),
            step: 'certificate-request',
            errorCode: 'app-dev.certificate_request_failed',
        );

        if (trim($request->stdout) === 'CURRENT') {
            return;
        }

        $certificate = $this->signer->sign($hostname, $request->stdout);
        $this->publish(
            node: $node,
            scope: $scope,
            hostname: $hostname,
            version: $version,
            certificate: $certificate,
            rootCertificate: $rootCertificate,
        );
    }

    /** @mago-expect lint:excessive-parameter-list Publication needs the complete certificate identity and payload. */
    private function publish(
        Node $node,
        string $scope,
        string $hostname,
        string $version,
        string $certificate,
        string $rootCertificate,
    ): void {
        $this->ssh->execute(
            $node,
            new RemoteCommand(
                arguments: [
                    'bash',
                    '-ceu',
                    $this->publishScript(),
                    '--',
                    $scope,
                    $hostname,
                    $version,
                    (string) strlen($certificate),
                ],
                input: $certificate.$rootCertificate,
            ),
            step: 'certificate-publish',
            errorCode: 'app-dev.certificate_publish_failed',
        );
    }

    private function publishScript(): string
    {
        return <<<'BASH'
            scope=$1
            hostname=$2
            version=$3
            certificate_length=$4
            root="/home/orbit/.orbit/certificates/$scope"
            candidate="$root/versions/$version.candidate"
            published="$root/versions/$version"
            test -d "$candidate"
            head -c "$certificate_length" > "$candidate/cert.pem"
            cat > "$candidate/root.pem"
            rm -f -- "$candidate/request.pem"
            chmod 0600 "$candidate/key.pem"
            chmod 0644 "$candidate/cert.pem" "$candidate/root.pem"
            openssl verify -CAfile "$candidate/root.pem" "$candidate/cert.pem"
            openssl x509 -in "$candidate/cert.pem" -noout -checkhost "$hostname"
            test "$(openssl pkey -in "$candidate/key.pem" -pubout 2>/dev/null)" = \
                "$(openssl x509 -in "$candidate/cert.pem" -pubkey -noout 2>/dev/null)"
            mv -fT -- "$candidate" "$published"
            target_link="$root/.current-$version"
            ln -s -- "$published" "$target_link"
            mv -fT -- "$target_link" "$root/current"

            caddy_root="/etc/caddy/orbit-certificates/$scope"
            caddy_candidate="$caddy_root/versions/$version.candidate"
            caddy_published="$caddy_root/versions/$version"
            sudo install -d -o root -g caddy -m 0750 -- "$caddy_root/versions" "$caddy_candidate"
            sudo install -o root -g caddy -m 0640 -- "$published/key.pem" "$caddy_candidate/key.pem"
            sudo install -o root -g caddy -m 0644 -- "$published/cert.pem" "$caddy_candidate/cert.pem"
            sudo mv -fT -- "$caddy_candidate" "$caddy_published"
            caddy_link="$caddy_root/.current-$version"
            sudo ln -s -- "$caddy_published" "$caddy_link"
            sudo mv -fT -- "$caddy_link" "$caddy_root/current"
            BASH;
    }

    private function remove(Node $node, string $scope): void
    {
        $this->ssh->execute(
            $node,
            new RemoteCommand(
                arguments: ['bash', '-seu', '--', $scope],
                input: <<<'BASH'
                    scope=$1
                    rm -rf -- "/home/orbit/.orbit/certificates/$scope"
                    sudo rm -rf -- "/etc/caddy/orbit-certificates/$scope"
                    BASH,
            ),
            step: 'certificate-remove',
            errorCode: 'app-dev.certificate_remove_failed',
        );
    }
}
