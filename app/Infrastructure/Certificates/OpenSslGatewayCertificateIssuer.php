<?php

declare(strict_types=1);

namespace App\Infrastructure\Certificates;

use App\Domain\Certificates\GatewayCertificateIssuer;
use App\Domain\Certificates\GatewayCertificatePaths;
use App\Domain\Nodes\NodeProvisioningException;
use App\Infrastructure\Files\AtomicSymlinkPublisher;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Processes\ProcessRunner;
use InvalidArgumentException;
use Throwable;

/** @mago-expect lint:cyclomatic-complexity Certificate issuance validates and publishes one protected immutable key pair. */
final readonly class OpenSslGatewayCertificateIssuer implements GatewayCertificateIssuer
{
    public function __construct(
        private ProcessRunner $processes,
        private OpenSslGatewayCertificateValidator $validator,
        private AtomicSymlinkPublisher $links,
        private string $orbitHome,
    ) {}

    public function issue(string $hostname, string $wireguardAddress): GatewayCertificatePaths
    {
        $this->guardIdentity($hostname, $wireguardAddress);
        $directory = rtrim(string: $this->orbitHome, characters: '/').'/ca';
        $paths = new GatewayCertificatePaths(
            privateKeyPath: $directory.'/gateway-current/gateway.key',
            certificatePath: $directory.'/gateway-current/gateway.pem',
        );

        if ($this->isCurrent($paths, $hostname, $wireguardAddress, $directory.'/root.pem')) {
            $this->protect($paths, $directory);

            return $paths;
        }

        $this->issueVersion($paths, $hostname, $wireguardAddress, $directory);
        $this->protect($paths, $directory);

        return $paths;
    }

    private function guardIdentity(string $hostname, string $wireguardAddress): void
    {
        if (filter_var($hostname, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
            throw new InvalidArgumentException("Gateway certificate hostname [{$hostname}] is invalid.");
        }

        if (filter_var($wireguardAddress, FILTER_VALIDATE_IP) === false) {
            throw new InvalidArgumentException("Gateway certificate IP address [{$wireguardAddress}] is invalid.");
        }
    }

    private function isCurrent(
        GatewayCertificatePaths $paths,
        string $hostname,
        string $wireguardAddress,
        string $rootCertificate,
    ): bool {
        if (! is_file($paths->privateKeyPath) || ! is_file($paths->certificatePath)) {
            return false;
        }

        return $this->validator->matches($paths, $hostname, $wireguardAddress, $rootCertificate);
    }

    private function issueVersion(
        GatewayCertificatePaths $currentPaths,
        string $hostname,
        string $wireguardAddress,
        string $caDirectory,
    ): void {
        $versionsDirectory = $caDirectory.'/gateway-versions';
        $version = bin2hex(random_bytes(8));
        $candidateDirectory = "{$versionsDirectory}/{$version}.candidate";
        $versionDirectory = "{$versionsDirectory}/{$version}";
        $candidatePaths = new GatewayCertificatePaths(
            privateKeyPath: $candidateDirectory.'/gateway.key',
            certificatePath: $candidateDirectory.'/gateway.pem',
        );
        $candidateRequest = $candidateDirectory.'/gateway.csr';
        $this->ensureVersionDirectory($versionsDirectory, $candidateDirectory);

        try {
            $this->generateCandidate(
                paths: $candidatePaths,
                requestPath: $candidateRequest,
                hostname: $hostname,
                wireguardAddress: $wireguardAddress,
                caDirectory: $caDirectory,
            );

            if (! $this->validator->matches(
                $candidatePaths,
                $hostname,
                $wireguardAddress,
                $caDirectory.'/root.pem',
            )) {
                throw new NodeProvisioningException(
                    step: 'gateway-certificate-validate',
                    errorCode: 'gateway.certificate_invalid',
                    message: 'The generated gateway certificate did not pass validation.',
                );
            }

            unlink($candidateRequest);

            if (! rename($candidateDirectory, $versionDirectory)) {
                throw new NodeProvisioningException(
                    step: 'gateway-certificate-install',
                    errorCode: 'gateway.certificate_install_failed',
                    message: 'Could not install the immutable gateway certificate version.',
                );
            }

            try {
                $this->links->publish($versionDirectory, dirname($currentPaths->certificatePath));
            } catch (Throwable $exception) {
                $this->cleanupVersion($versionDirectory);

                throw new NodeProvisioningException(
                    step: 'gateway-certificate-publish',
                    errorCode: 'gateway.certificate_publish_failed',
                    message: 'Could not atomically publish the gateway certificate pair.',
                    previous: $exception,
                );
            }
        } finally {
            $this->cleanupVersion($candidateDirectory);
        }
    }

    private function ensureVersionDirectory(string $versionsDirectory, string $candidateDirectory): void
    {
        foreach ([$versionsDirectory, $candidateDirectory] as $directory) {
            if (! is_dir($directory) && ! mkdir(directory: $directory, permissions: 0o700, recursive: true)) {
                throw new NodeProvisioningException(
                    step: 'gateway-certificate-directory',
                    errorCode: 'gateway.certificate_directory_failed',
                    message: "Could not create gateway certificate directory [{$directory}].",
                );
            }

            chmod(filename: $directory, permissions: 0o700);
        }
    }

    private function generateCandidate(
        GatewayCertificatePaths $paths,
        string $requestPath,
        string $hostname,
        string $wireguardAddress,
        string $caDirectory,
    ): void {
        $this->run(
            step: 'gateway-certificate-key',
            errorCode: 'gateway.certificate_key_failed',
            arguments: ['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', $paths->privateKeyPath],
        );
        chmod(filename: $paths->privateKeyPath, permissions: 0o600);
        $this->run(
            step: 'gateway-certificate-request',
            errorCode: 'gateway.certificate_request_failed',
            arguments: [
                'openssl',
                'req',
                '-new',
                '-key',
                $paths->privateKeyPath,
                '-out',
                $requestPath,
                '-subj',
                "/CN={$hostname}",
                '-addext',
                "subjectAltName=DNS:{$hostname},IP:{$wireguardAddress}",
            ],
        );
        $this->run(
            step: 'gateway-certificate-sign',
            errorCode: 'gateway.certificate_sign_failed',
            arguments: [
                'openssl',
                'x509',
                '-req',
                '-in',
                $requestPath,
                '-CA',
                $caDirectory.'/root.pem',
                '-CAkey',
                $caDirectory.'/root.key',
                '-CAserial',
                $caDirectory.'/root.srl',
                '-CAcreateserial',
                '-out',
                $paths->certificatePath,
                '-days',
                '825',
                '-copy_extensions',
                'copy',
            ],
        );
        chmod(filename: $paths->certificatePath, permissions: 0o644);
    }

    private function protect(GatewayCertificatePaths $paths, string $caDirectory): void
    {
        chmod(filename: $caDirectory, permissions: 0o700);
        chmod(filename: dirname($paths->certificatePath), permissions: 0o700);
        chmod(filename: $paths->privateKeyPath, permissions: 0o600);
        chmod(filename: $paths->certificatePath, permissions: 0o644);
        $serialPath = $caDirectory.'/root.srl';

        if (is_file($serialPath)) {
            chmod(filename: $serialPath, permissions: 0o600);
        }
    }

    private function cleanupVersion(string $directory): void
    {
        if (! is_dir($directory)) {
            return;
        }

        foreach (['gateway.key', 'gateway.pem', 'gateway.csr'] as $filename) {
            $path = "{$directory}/{$filename}";

            if (is_file($path)) {
                unlink($path);
            }
        }

        rmdir($directory);
    }

    /** @param non-empty-list<string> $arguments */
    private function run(string $step, string $errorCode, array $arguments): CommandResult
    {
        $result = $this->processes->run(new ProcessInvocation($arguments, timeout: 60.0));

        if (! $result->succeeded()) {
            throw new NodeProvisioningException(
                step: $step,
                errorCode: $errorCode,
                message: "Gateway certificate step [{$step}] failed.",
                result: $result,
            );
        }

        return $result;
    }
}
