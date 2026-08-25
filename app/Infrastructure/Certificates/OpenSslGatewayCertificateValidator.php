<?php

declare(strict_types=1);

namespace App\Infrastructure\Certificates;

use App\Domain\Certificates\GatewayCertificatePaths;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Processes\ProcessRunner;

final readonly class OpenSslGatewayCertificateValidator
{
    public function __construct(
        private ProcessRunner $processes,
    ) {}

    public function matches(
        GatewayCertificatePaths $paths,
        string $hostname,
        string $wireguardAddress,
        string $rootCertificate,
    ): bool {
        $checks = [
            ['openssl', 'verify', '-CAfile', $rootCertificate, $paths->certificatePath],
            ['openssl', 'x509', '-in', $paths->certificatePath, '-noout', '-checkend', '86400'],
            ['openssl', 'x509', '-in', $paths->certificatePath, '-noout', '-checkhost', $hostname],
            ['openssl', 'x509', '-in', $paths->certificatePath, '-noout', '-checkip', $wireguardAddress],
        ];

        foreach ($checks as $arguments) {
            if (! $this->processes->run(new ProcessInvocation($arguments, timeout: 60.0))->succeeded()) {
                return false;
            }
        }

        $certificatePublicKey = $this->processes->run(new ProcessInvocation([
            'openssl',
            'x509',
            '-in',
            $paths->certificatePath,
            '-pubkey',
            '-noout',
        ], timeout: 60.0));
        $privatePublicKey = $this->processes->run(new ProcessInvocation([
            'openssl',
            'pkey',
            '-in',
            $paths->privateKeyPath,
            '-pubout',
        ], timeout: 60.0));

        return (
            $certificatePublicKey->succeeded()
            && $privatePublicKey->succeeded()
            && trim($certificatePublicKey->stdout) === trim($privatePublicKey->stdout)
        );
    }
}
