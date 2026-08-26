<?php

declare(strict_types=1);

namespace App\Actions\Gateway;

use App\Actions\Nodes\AssignRoleAction;
use App\Data\Gateway\BootstrapGatewayData;
use App\Domain\Gateway\GatewayVpnConverger;
use App\Domain\Gateway\GatewayWebConverger;
use App\Domain\Nodes\NodeProvisioningException;
use App\Domain\Nodes\RoleName;
use App\Domain\Shared\LifecycleStatus;
use App\Domain\WireGuard\VpnSettings;
use App\Infrastructure\Files\ProtectedFileWriter;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Processes\ProcessRunner;
use App\Models\Node;
use Throwable;

/**
 * @mago-expect lint:cyclomatic-complexity
 * @mago-expect lint:excessive-parameter-list
 * @mago-expect lint:kan-defect
 * @mago-expect lint:too-many-methods
 */
final readonly class BootstrapGatewayAction
{
    public function __construct(
        private AssignRoleAction $assignRole,
        private GatewayBootstrapIdentityValidator $identity,
        private VpnSettings $vpnSettings,
        private ProcessRunner $processes,
        private ProtectedFileWriter $files,
        private GatewayVpnConverger $vpn,
        private GatewayWebConverger $web,
        private string $orbitHome,
    ) {}

    public function execute(BootstrapGatewayData $data): Node
    {
        $this->identity->validate($data);

        $node = Node::query()->updateOrCreate(
            ['name' => $data->name],
            [
                'status' => LifecycleStatus::Provisioning,
                'platform' => 'linux',
                'architecture' => php_uname('m'),
                'public_ssh_host' => $data->publicHost,
                'public_ssh_port' => 22,
                'ssh_user' => 'orbit',
                'wireguard_address' => $data->wireguardAddress,
                'failed_step' => null,
                'error_code' => null,
            ],
        );

        try {
            foreach ([RoleName::Gateway, RoleName::Vpn] as $role) {
                $this->assignRole
                    ->execute($node, $role)
                    ->update([
                        'status' => LifecycleStatus::Provisioning,
                        'failed_step' => null,
                        'error_code' => null,
                    ]);
            }

            $this->vpnSettings->configure(
                subnet: $data->wireguardSubnet,
                port: $data->wireguardPort,
                endpoint: $data->wireguardEndpoint,
                dnsServer: $data->dnsServer,
                domain: $data->domain,
                privateInterface: $data->privateInterface,
            );

            $this->ensureDirectories();
            $this->ensureSshKeys();
            $wireGuardPublicKey = $this->ensureWireGuardKeys();
            $node->update(['wireguard_public_key' => $wireGuardPublicKey]);
            $this->ensureCertificateAuthority();
            $this->vpn->converge($node, $data);
            $this->web->converge("{$data->name}.{$data->domain}", $data->wireguardAddress);
        } catch (Throwable $exception) {
            $failure = $exception instanceof NodeProvisioningException
                ? $exception
                : new NodeProvisioningException(
                    step: 'unknown',
                    errorCode: 'gateway.bootstrap_failed',
                    message: 'Gateway bootstrap failed.',
                    previous: $exception,
                );
            $this->markFailed($node, $failure);

            throw $failure;
        }

        $active = [
            'status' => LifecycleStatus::Active,
            'failed_step' => null,
            'error_code' => null,
        ];
        $node->update($active);
        $node->roles()->update($active);

        return $node->load('roles');
    }

    private function markFailed(Node $node, NodeProvisioningException $exception): void
    {
        $failure = [
            'status' => LifecycleStatus::Failed,
            'failed_step' => $exception->step,
            'error_code' => $exception->errorCode,
        ];
        $node->update($failure);
        $node->roles()->update($failure);
    }

    private function ensureDirectories(): void
    {
        foreach (['', 'ca', 'generated', 'logs', 'ssh', 'wireguard'] as $directory) {
            $path = rtrim(string: $this->orbitHome.'/'.$directory, characters: '/');

            if (! is_dir($path) && ! mkdir(directory: $path, permissions: 0o700, recursive: true) && ! is_dir($path)) {
                throw new NodeProvisioningException(
                    step: 'gateway-directories',
                    errorCode: 'gateway.directory_failed',
                    message: "Could not create gateway directory [{$path}].",
                );
            }

            chmod(filename: $path, permissions: 0o700);
        }
    }

    private function ensureSshKeys(): void
    {
        $privateKey = $this->orbitHome.'/ssh/id_ed25519';

        if (! is_file($privateKey) || ! is_file($privateKey.'.pub')) {
            $this->run('gateway-ssh-key', 'gateway.ssh_key_failed', [
                'ssh-keygen',
                '-q',
                '-t',
                'ed25519',
                '-N',
                '',
                '-C',
                'orbit-gateway',
                '-f',
                $privateKey,
            ]);
        }

        chmod(filename: $privateKey, permissions: 0o600);
        chmod(filename: $privateKey.'.pub', permissions: 0o644);
    }

    private function ensureWireGuardKeys(): string
    {
        $privatePath = $this->orbitHome.'/wireguard/private.key';
        $publicPath = $this->orbitHome.'/wireguard/public.key';

        if (! is_file($privatePath)) {
            $privateKey = trim($this->run(
                'wireguard-private-key',
                'vpn.key_generation_failed',
                ['wg', 'genkey'],
            )->stdout);
            $this->files->put($privatePath, $privateKey.PHP_EOL);
        }

        $privateKey = file_get_contents($privatePath);

        if (! is_string($privateKey) || trim($privateKey) === '') {
            throw new NodeProvisioningException(
                step: 'wireguard-private-key',
                errorCode: 'vpn.key_generation_failed',
                message: 'The gateway WireGuard private key is invalid.',
            );
        }

        if (! is_file($publicPath)) {
            $publicKey = trim($this->run(
                'wireguard-public-key',
                'vpn.key_generation_failed',
                ['wg', 'pubkey'],
                input: $privateKey,
            )->stdout);
            $this->files->put($publicPath, $publicKey.PHP_EOL, 0o644);
        }

        $publicKey = file_get_contents($publicPath);

        if (! is_string($publicKey) || trim($publicKey) === '') {
            throw new NodeProvisioningException(
                step: 'wireguard-public-key',
                errorCode: 'vpn.key_generation_failed',
                message: 'The gateway WireGuard public key is invalid.',
            );
        }

        return trim($publicKey);
    }

    private function ensureCertificateAuthority(): void
    {
        $caDirectory = $this->orbitHome.'/ca';
        $lockPath = $caDirectory.'/root.lock';
        $lock = fopen(filename: $lockPath, mode: 'c+');

        if ($lock === false) {
            throw new NodeProvisioningException(
                step: 'ca-root-lock',
                errorCode: 'ca.lock_failed',
                message: 'Could not open the Orbit root CA publication lock.',
            );
        }

        try {
            chmod(filename: $lockPath, permissions: 0o600);

            if (! flock($lock, LOCK_EX)) {
                throw new NodeProvisioningException(
                    step: 'ca-root-lock',
                    errorCode: 'ca.lock_failed',
                    message: 'Could not acquire the Orbit root CA publication lock.',
                );
            }

            $this->ensureLockedCertificateAuthority($caDirectory);
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private function ensureLockedCertificateAuthority(string $caDirectory): void
    {
        $privateKey = $caDirectory.'/root.key';
        $certificate = $caDirectory.'/root.pem';
        $candidateDirectory = $caDirectory.'/.root-ca.candidate';
        $privateKeyExists = is_file($privateKey);
        $certificateExists = is_file($certificate);

        if ($privateKeyExists !== $certificateExists) {
            throw new NodeProvisioningException(
                step: 'ca-root-validate',
                errorCode: 'ca.invalid_state',
                message: 'The Orbit root CA state is partial; restore the missing root file.',
            );
        }

        $this->cleanupCertificateAuthorityCandidate($candidateDirectory);

        if ($privateKeyExists && $certificateExists) {
            if (! $this->certificateAuthorityPairIsValid($privateKey, $certificate)) {
                throw new NodeProvisioningException(
                    step: 'ca-root-validate',
                    errorCode: 'ca.invalid_state',
                    message: 'The existing Orbit root CA key and certificate pair is invalid.',
                );
            }

            $this->protectCertificateAuthorityPair($privateKey, $certificate);

            return;
        }

        $candidatePrivateKey = $candidateDirectory.'/root.key';
        $candidateCertificate = $candidateDirectory.'/root.pem';

        try {
            if (! mkdir(directory: $candidateDirectory, permissions: 0o700) && ! is_dir($candidateDirectory)) {
                throw new NodeProvisioningException(
                    step: 'ca-root-candidate',
                    errorCode: 'ca.candidate_failed',
                    message: 'Could not create the Orbit root CA candidate directory.',
                );
            }

            chmod(filename: $candidateDirectory, permissions: 0o700);
            $this->run('ca-private-key', 'ca.key_generation_failed', [
                'openssl',
                'genpkey',
                '-algorithm',
                'ED25519',
                '-out',
                $candidatePrivateKey,
            ]);
            chmod(filename: $candidatePrivateKey, permissions: 0o600);
            $this->run('ca-root-certificate', 'ca.certificate_generation_failed', [
                'openssl',
                'req',
                '-x509',
                '-new',
                '-key',
                $candidatePrivateKey,
                '-out',
                $candidateCertificate,
                '-days',
                '3650',
                '-subj',
                '/CN=Orbit Root CA',
                '-addext',
                'basicConstraints=critical,CA:TRUE',
                '-addext',
                'keyUsage=critical,keyCertSign,cRLSign',
            ]);
            chmod(filename: $candidateCertificate, permissions: 0o644);

            if (! $this->certificateAuthorityPairIsValid($candidatePrivateKey, $candidateCertificate)) {
                throw new NodeProvisioningException(
                    step: 'ca-root-validate',
                    errorCode: 'ca.invalid_candidate',
                    message: 'The generated Orbit root CA key and certificate pair is invalid.',
                );
            }

            $this->publishCertificateAuthorityPair(
                $candidatePrivateKey,
                $candidateCertificate,
                $privateKey,
                $certificate,
            );
            $this->protectCertificateAuthorityPair($privateKey, $certificate);
        } finally {
            $this->cleanupCertificateAuthorityCandidate($candidateDirectory);
        }
    }

    private function certificateAuthorityPairIsValid(string $privateKeyPath, string $certificatePath): bool
    {
        $certificate = file_get_contents($certificatePath);
        $privateKey = file_get_contents($privateKeyPath);

        if (! is_string($certificate) || ! is_string($privateKey)) {
            return false;
        }

        /** @mago-expect analysis:invalid-argument OpenSSL accepts PEM strings at runtime. */
        $parsedCertificate = openssl_x509_read(certificate: $certificate);
        $parsedPrivateKey = openssl_pkey_get_private($privateKey);
        $details = $parsedCertificate !== false ? openssl_x509_parse($parsedCertificate) : false;
        /** @mago-expect analysis:mixed-assignment OpenSSL certificate fields are untyped. */
        $basicConstraints = is_array($details)
            ? $details['extensions']['basicConstraints'] ?? null
            : null;
        $validFrom = is_array($details) ? $details['validFrom_time_t'] : null;
        $validTo = is_array($details) ? $details['validTo_time_t'] : null;
        $now = time();

        return (
            $parsedCertificate !== false
            && $parsedPrivateKey !== false
            && is_string($basicConstraints)
            && str_contains($basicConstraints, 'CA:TRUE')
            && is_int($validFrom)
            && $validFrom <= $now
            && is_int($validTo)
            && $validTo >= $now
            && openssl_x509_check_private_key($parsedCertificate, $parsedPrivateKey)
        );
    }

    private function publishCertificateAuthorityPair(
        string $candidatePrivateKey,
        string $candidateCertificate,
        string $privateKey,
        string $certificate,
    ): void {
        $privateKeyPublished = false;

        try {
            if (! rename($candidatePrivateKey, $privateKey)) {
                throw new \RuntimeException('Could not publish the Orbit root CA private key.');
            }

            $privateKeyPublished = true;

            if (! rename($candidateCertificate, $certificate)) {
                throw new \RuntimeException('Could not publish the Orbit root CA certificate.');
            }
        } catch (Throwable $exception) {
            if ($privateKeyPublished && is_file($privateKey)) {
                rename($privateKey, $candidatePrivateKey);
            }

            throw new NodeProvisioningException(
                step: 'ca-root-publish',
                errorCode: 'ca.publish_failed',
                message: 'Could not publish the validated Orbit root CA pair.',
                previous: $exception,
            );
        }
    }

    private function protectCertificateAuthorityPair(string $privateKey, string $certificate): void
    {
        chmod(filename: $privateKey, permissions: 0o600);
        chmod(filename: $certificate, permissions: 0o644);
    }

    private function cleanupCertificateAuthorityCandidate(string $directory): void
    {
        if (! is_dir($directory)) {
            return;
        }

        foreach (['root.key', 'root.pem'] as $filename) {
            $path = $directory.'/'.$filename;

            if (is_file($path)) {
                unlink($path);
            }
        }

        rmdir($directory);
    }

    /** @param non-empty-list<string> $arguments */
    private function run(
        string $step,
        string $errorCode,
        array $arguments,
        ?string $input = null,
    ): \App\Infrastructure\Processes\CommandResult {
        $result = $this->processes->run(new ProcessInvocation(
            arguments: $arguments,
            timeout: 60.0,
            input: $input,
        ));

        if (! $result->succeeded()) {
            throw new NodeProvisioningException(
                step: $step,
                errorCode: $errorCode,
                message: "Gateway bootstrap step [{$step}] failed.",
                result: $result,
            );
        }

        return $result;
    }
}
