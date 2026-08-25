<?php

declare(strict_types=1);

namespace App\Infrastructure\Certificates;

use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\Certificates\LeafCertificateSigner;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Processes\ProcessRunner;
use RuntimeException;

final readonly class OpenSslLeafCertificateSigner implements LeafCertificateSigner
{
    public function __construct(
        private ProcessRunner $processes,
        private string $orbitHome,
    ) {}

    public function sign(string $hostname, string $certificateRequest): string
    {
        if (filter_var($hostname, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
            throw new RuntimeException("Certificate hostname [{$hostname}] is invalid.");
        }

        $validation = $this->processes->run(new ProcessInvocation(
            arguments: ['openssl', 'req', '-in', '/dev/stdin', '-noout', '-verify'],
            timeout: 60.0,
            input: $certificateRequest,
        ));

        if (! $validation->succeeded()) {
            throw new RuntimeConvergenceException(
                step: 'certificate-request-validate',
                errorCode: 'app-dev.certificate_request_invalid',
                message: "Certificate request for [{$hostname}] is invalid.",
                result: $validation,
            );
        }

        $extensions = tempnam(directory: sys_get_temp_dir(), prefix: 'orbit-leaf-');

        if (! is_string($extensions)) {
            throw new RuntimeException('Could not create a leaf certificate extension file.');
        }

        try {
            $this->writeExtensions($extensions, $hostname);
            $caDirectory = rtrim(string: $this->orbitHome, characters: '/').'/ca';
            $result = $this->processes->run(new ProcessInvocation(
                arguments: [
                    'openssl',
                    'x509',
                    '-req',
                    '-in',
                    '/dev/stdin',
                    '-CA',
                    $caDirectory.'/root.pem',
                    '-CAkey',
                    $caDirectory.'/root.key',
                    '-set_serial',
                    '0x'.bin2hex(random_bytes(20)),
                    '-days',
                    '825',
                    '-sha256',
                    '-extfile',
                    $extensions,
                    '-extensions',
                    'leaf',
                ],
                timeout: 60.0,
                input: $certificateRequest,
            ));
        } finally {
            unlink($extensions);
        }

        if (! $result->succeeded() || ! str_contains($result->stdout, 'BEGIN CERTIFICATE')) {
            throw new RuntimeConvergenceException(
                step: 'certificate-sign',
                errorCode: 'app-dev.certificate_sign_failed',
                message: "Could not sign the certificate for [{$hostname}].",
                result: $result,
            );
        }

        return $result->stdout;
    }

    public function rootCertificate(): string
    {
        $path = rtrim(string: $this->orbitHome, characters: '/').'/ca/root.pem';
        $certificate = file_get_contents($path);

        if (! is_string($certificate) || ! str_contains($certificate, 'BEGIN CERTIFICATE')) {
            throw new RuntimeException("Orbit root certificate [{$path}] is missing or invalid.");
        }

        return $certificate;
    }

    private function writeExtensions(string $path, string $hostname): void
    {
        $contents = <<<EXTENSIONS
            [leaf]
            basicConstraints = critical,CA:FALSE
            keyUsage = critical,digitalSignature,keyEncipherment
            extendedKeyUsage = serverAuth
            subjectAltName = DNS:{$hostname}
            EXTENSIONS;

        if (file_put_contents($path, $contents) === false) {
            throw new RuntimeException('Could not write leaf certificate extensions.');
        }

        chmod(filename: $path, permissions: 0o600);
    }
}
