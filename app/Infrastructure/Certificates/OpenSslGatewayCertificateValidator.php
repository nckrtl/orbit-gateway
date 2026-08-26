<?php

declare(strict_types=1);

namespace App\Infrastructure\Certificates;

use App\Domain\Certificates\GatewayCertificatePaths;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Processes\ProcessRunner;

/** @mago-expect lint:cyclomatic-complexity Gateway certificate validation fails closed across each trust-policy check. */
final readonly class OpenSslGatewayCertificateValidator
{
    private const int MAXIMUM_VALIDITY_SECONDS = 397 * 24 * 60 * 60;

    private const string RENEW_IF_WITHIN_SECONDS = '2592000';

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
            [
                'openssl',
                'x509',
                '-in',
                $paths->certificatePath,
                '-noout',
                '-checkend',
                self::RENEW_IF_WITHIN_SECONDS,
            ],
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

        if (
            ! $certificatePublicKey->succeeded()
            || ! $privatePublicKey->succeeded()
            || trim($certificatePublicKey->stdout) !== trim($privatePublicKey->stdout)
            || ! $this->hasEd25519KeyPair($paths)
        ) {
            return false;
        }

        $validity = $this->processes->run(new ProcessInvocation([
            'openssl',
            'x509',
            '-in',
            $paths->certificatePath,
            '-noout',
            '-dates',
        ], timeout: 60.0));
        /** @var array<int, string> $notBefore */
        $notBefore = [];
        /** @var array<int, string> $notAfter */
        $notAfter = [];

        if (
            ! $validity->succeeded()
            || preg_match('/^notBefore=(.+)$/m', $validity->stdout, $notBefore) !== 1
            || preg_match('/^notAfter=(.+)$/m', $validity->stdout, $notAfter) !== 1
        ) {
            return false;
        }

        $validFrom = strtotime($notBefore[1]);
        $validTo = strtotime($notAfter[1]);

        return (
            is_int($validFrom)
            && is_int($validTo)
            && $validTo >= $validFrom
            && ($validTo - $validFrom) <= self::MAXIMUM_VALIDITY_SECONDS
            && $this->hasExpectedExtensions($paths->certificatePath, $hostname, $wireguardAddress)
        );
    }

    private function hasExpectedExtensions(
        string $certificatePath,
        string $hostname,
        string $wireguardAddress,
    ): bool {
        $certificate = file_get_contents($certificatePath);

        if (! is_string($certificate)) {
            return false;
        }

        $details = openssl_x509_parse($certificate);
        $extensions = is_array($details) ? $details['extensions'] : null;

        if (! is_array($extensions)) {
            return false;
        }

        $text = $this->processes->run(new ProcessInvocation([
            'openssl',
            'x509',
            '-in',
            $certificatePath,
            '-noout',
            '-text',
        ], timeout: 60.0));

        if (! $text->succeeded()) {
            return false;
        }

        return (
            ($extensions['basicConstraints'] ?? null) === 'CA:FALSE'
            && $this->hasCriticalExtension($text->stdout, 'Basic Constraints')
            && $this->hasExactUsage($extensions['keyUsage'] ?? null, ['Digital Signature'])
            && $this->hasCriticalExtension($text->stdout, 'Key Usage')
            && $this->hasExactUsage($extensions['extendedKeyUsage'] ?? null, [
                'TLS Web Server Authentication',
            ])
            && $this->hasExactSubjectAltNames(
                $extensions['subjectAltName'] ?? null,
                $hostname,
                $wireguardAddress,
            )
        );
    }

    private function hasCriticalExtension(string $certificateText, string $extension): bool
    {
        return (
            preg_match(
                '/X509v3 '.preg_quote(str: $extension, delimiter: '/').': critical\s*\R/',
                $certificateText,
            ) === 1
        );
    }

    /** @param list<string> $expected */
    private function hasExactUsage(mixed $usage, array $expected): bool
    {
        if (! is_string($usage)) {
            return false;
        }

        $actual = array_map(trim(...), explode(',', $usage));
        sort($actual);
        sort($expected);

        return $actual === $expected;
    }

    private function hasExactSubjectAltNames(mixed $subjectAltNames, string $hostname, string $wireguardAddress): bool
    {
        if (! is_string($subjectAltNames)) {
            return false;
        }

        $names = array_map(trim(...), explode(',', $subjectAltNames));

        if (count($names) !== 2 || ! in_array("DNS:{$hostname}", $names, strict: true)) {
            return false;
        }

        foreach ($names as $name) {
            if (! str_starts_with($name, 'IP Address:')) {
                continue;
            }

            $address = substr($name, strlen('IP Address:'));

            return inet_pton($address) === inet_pton($wireguardAddress);
        }

        return false;
    }

    private function hasEd25519KeyPair(GatewayCertificatePaths $paths): bool
    {
        if (! is_file($paths->certificatePath) || ! is_file($paths->privateKeyPath)) {
            return false;
        }

        $certificate = file_get_contents($paths->certificatePath);
        $privateKey = file_get_contents($paths->privateKeyPath);

        if (! is_string($certificate) || ! is_string($privateKey)) {
            return false;
        }

        $publicKey = openssl_pkey_get_public($certificate);
        $parsedPrivateKey = openssl_pkey_get_private($privateKey);

        if ($publicKey === false || $parsedPrivateKey === false) {
            return false;
        }

        $publicDetails = openssl_pkey_get_details($publicKey);
        $privateDetails = openssl_pkey_get_details($parsedPrivateKey);

        return (
            is_array($publicDetails)
            && ($publicDetails['type'] ?? null) === OPENSSL_KEYTYPE_ED25519
            && is_array($privateDetails)
            && ($privateDetails['type'] ?? null) === OPENSSL_KEYTYPE_ED25519
        );
    }
}
