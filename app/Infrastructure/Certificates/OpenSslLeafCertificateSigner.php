<?php

declare(strict_types=1);

namespace App\Infrastructure\Certificates;

use App\Domain\AppDev\RuntimeConvergenceException;
use App\Domain\Certificates\LeafCertificateSigner;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Processes\ProcessRunner;
use Closure;
use RuntimeException;

/** @mago-expect lint:cyclomatic-complexity Root validation and signing fail closed at each trust boundary. */
final readonly class OpenSslLeafCertificateSigner implements LeafCertificateSigner
{
    private const string LEAF_VALIDITY_DAYS = '397';

    /** @var Closure(): int */
    private Closure $clock;

    /** @param null|(Closure(): int) $clock */
    public function __construct(
        private ProcessRunner $processes,
        private string $orbitHome,
        ?Closure $clock = null,
    ) {
        $this->clock = $clock ?? time(...);
    }

    public function sign(string $hostname, string $certificateRequest): string
    {
        if (filter_var($hostname, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
            throw new RuntimeException("Certificate hostname [{$hostname}] is invalid.");
        }

        $this->rootCertificate();

        $validation = $this->processes->run(new ProcessInvocation(
            arguments: ['openssl', 'req', '-in', '/dev/stdin', '-noout', '-verify'],
            timeout: 60.0,
            input: $certificateRequest,
        ));

        if (! $validation->succeeded() || ! $this->hasEd25519PublicKey($certificateRequest)) {
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
                    self::LEAF_VALIDITY_DAYS,
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
        $directory = rtrim(string: $this->orbitHome, characters: '/').'/ca';
        $lockPath = $directory.'/root.lock';
        $lock = fopen(filename: $lockPath, mode: 'c+');

        if ($lock === false) {
            throw new RuntimeException('Orbit root CA material is not readable.');
        }

        try {
            chmod(filename: $lockPath, permissions: 0o600);

            if (! flock($lock, LOCK_SH)) {
                throw new RuntimeException('Orbit root CA material is not readable.');
            }

            return $this->readRootCertificate($directory);
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    private function readRootCertificate(string $directory): string
    {
        $certificatePath = $directory.'/root.pem';
        $privateKeyPath = $directory.'/root.key';
        $certificateExists = is_file($certificatePath);
        $privateKeyExists = is_file($privateKeyPath);

        if ($certificateExists !== $privateKeyExists) {
            throw new RuntimeException('Orbit root CA state is partial; restore the missing root file.');
        }

        if (! $certificateExists) {
            throw new RuntimeException('Orbit root CA is not bootstrapped.');
        }

        $certificate = file_get_contents($certificatePath);
        $privateKey = file_get_contents($privateKeyPath);

        if (! is_string($certificate) || ! is_string($privateKey)) {
            throw new RuntimeException('Orbit root CA material is not readable.');
        }

        /** @mago-expect analysis:invalid-argument OpenSSL accepts PEM strings at runtime. */
        $parsedCertificate = openssl_x509_read(certificate: $certificate);
        $parsedPrivateKey = openssl_pkey_get_private($privateKey);
        $details = $parsedCertificate !== false ? openssl_x509_parse($parsedCertificate) : false;
        /** @mago-expect analysis:mixed-assignment OpenSSL certificate extension values are untyped. */
        $basicConstraints = is_array($details)
            ? $details['extensions']['basicConstraints'] ?? null
            : null;
        $validFrom = is_array($details) ? $details['validFrom_time_t'] : null;
        $validTo = is_array($details) ? $details['validTo_time_t'] : null;
        $now = ($this->clock)();

        if (
            $parsedCertificate === false
            || $parsedPrivateKey === false
            || ! is_string($basicConstraints)
            || ! str_contains($basicConstraints, 'CA:TRUE')
            || ! is_int($validFrom)
            || $validFrom > $now
            || ! is_int($validTo)
            || $validTo < $now
            || ! openssl_x509_check_private_key($parsedCertificate, $parsedPrivateKey)
        ) {
            throw new RuntimeException('Orbit root CA material is invalid.');
        }

        return $certificate;
    }

    private function writeExtensions(string $path, string $hostname): void
    {
        $contents = <<<EXTENSIONS
            [leaf]
            basicConstraints = critical,CA:FALSE
            keyUsage = critical,digitalSignature
            extendedKeyUsage = serverAuth
            subjectAltName = DNS:{$hostname}
            EXTENSIONS;

        if (file_put_contents($path, $contents) === false) {
            throw new RuntimeException('Could not write leaf certificate extensions.');
        }

        chmod(filename: $path, permissions: 0o600);
    }

    private function hasEd25519PublicKey(string $certificateRequest): bool
    {
        $publicKey = openssl_csr_get_public_key($certificateRequest);

        if ($publicKey === false) {
            return false;
        }

        $details = openssl_pkey_get_details($publicKey);

        return is_array($details) && ($details['type'] ?? null) === OPENSSL_KEYTYPE_ED25519;
    }
}
