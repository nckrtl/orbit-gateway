<?php

declare(strict_types=1);

namespace App\Infrastructure\Gateway;

use App\Domain\Certificates\GatewayCertificatePaths;
use App\Domain\Nodes\NodeProvisioningException;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Processes\ProcessRunner;

final readonly class NativeGatewayCertificatePublisher
{
    public function __construct(
        private ProcessRunner $processes,
        private string $orbitHome,
    ) {}

    public function publish(GatewayCertificatePaths $certificate): void
    {
        $version = bin2hex(random_bytes(8));
        $versionsDirectory = '/etc/caddy/orbit-cert-versions';
        $candidateDirectory = "{$versionsDirectory}/{$version}.candidate";
        $versionDirectory = "{$versionsDirectory}/{$version}";
        $candidateLink = "/etc/caddy/orbit-cert-current.candidate.{$version}";

        try {
            $this->stage($certificate, $versionsDirectory, $candidateDirectory);
            $this->validate($candidateDirectory);
            $this->run(
                step: 'gateway-certificate-stage',
                errorCode: 'gateway.certificate_install_failed',
                arguments: ['sudo', 'mv', '-f', '--', $candidateDirectory, $versionDirectory],
            );
            $this->run(
                step: 'gateway-certificate-publish',
                errorCode: 'gateway.certificate_publish_failed',
                arguments: ['sudo', 'ln', '-s', '--', $versionDirectory, $candidateLink],
            );
            $this->run(
                step: 'gateway-certificate-publish',
                errorCode: 'gateway.certificate_publish_failed',
                arguments: ['sudo', 'mv', '-Tf', '--', $candidateLink, '/etc/caddy/orbit-cert-current'],
            );
        } catch (NodeProvisioningException $exception) {
            $this->cleanup([$candidateDirectory, $versionDirectory, $candidateLink]);

            throw $exception;
        }
    }

    private function stage(
        GatewayCertificatePaths $certificate,
        string $versionsDirectory,
        string $candidateDirectory,
    ): void {
        foreach ([$versionsDirectory, $candidateDirectory] as $directory) {
            $this->run(
                step: 'gateway-certificate-stage',
                errorCode: 'gateway.certificate_install_failed',
                arguments: ['sudo', 'install', '-d', '-o', 'root', '-g', 'caddy', '-m', '0750', $directory],
            );
        }

        foreach ([
            $certificate->certificatePath => $candidateDirectory.'/gateway.pem',
            $certificate->privateKeyPath => $candidateDirectory.'/gateway.key',
        ] as $source => $destination) {
            $this->run(
                step: 'gateway-certificate-stage',
                errorCode: 'gateway.certificate_install_failed',
                arguments: [
                    'sudo',
                    'install',
                    '-o',
                    'root',
                    '-g',
                    'caddy',
                    '-m',
                    '0640',
                    '--',
                    $source,
                    $destination,
                ],
            );
        }
    }

    private function validate(string $candidateDirectory): void
    {
        $this->run(
            step: 'gateway-certificate-validate',
            errorCode: 'gateway.certificate_invalid',
            arguments: [
                'sudo',
                'openssl',
                'verify',
                '-CAfile',
                rtrim(string: $this->orbitHome, characters: '/').'/ca/root.pem',
                $candidateDirectory.'/gateway.pem',
            ],
        );
        $certificatePublicKey = $this->run(
            step: 'gateway-certificate-validate',
            errorCode: 'gateway.certificate_invalid',
            arguments: ['sudo', 'openssl', 'x509', '-in', $candidateDirectory.'/gateway.pem', '-pubkey', '-noout'],
        );
        $privatePublicKey = $this->run(
            step: 'gateway-certificate-validate',
            errorCode: 'gateway.certificate_invalid',
            arguments: ['sudo', 'openssl', 'pkey', '-in', $candidateDirectory.'/gateway.key', '-pubout'],
        );

        if (trim($certificatePublicKey->stdout) !== trim($privatePublicKey->stdout)) {
            throw new NodeProvisioningException(
                step: 'gateway-certificate-validate',
                errorCode: 'gateway.certificate_invalid',
                message: 'The staged Caddy certificate and private key do not match.',
            );
        }
    }

    /** @param non-empty-list<string> $paths */
    private function cleanup(array $paths): void
    {
        $this->processes->run(new ProcessInvocation(['sudo', 'rm', '-rf', '--', ...$paths]));
    }

    /** @param non-empty-list<string> $arguments */
    private function run(string $step, string $errorCode, array $arguments): CommandResult
    {
        $result = $this->processes->run(new ProcessInvocation(arguments: $arguments, timeout: 60.0));

        if (! $result->succeeded()) {
            throw new NodeProvisioningException(
                step: $step,
                errorCode: $errorCode,
                message: "Gateway certificate publication step [{$step}] failed.",
                result: $result,
            );
        }

        return $result;
    }
}
