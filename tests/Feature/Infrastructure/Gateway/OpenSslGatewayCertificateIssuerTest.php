<?php

declare(strict_types=1);

use App\Infrastructure\Certificates\OpenSslGatewayCertificateIssuer;
use App\Infrastructure\Certificates\OpenSslGatewayCertificateValidator;
use App\Infrastructure\Files\AtomicSymlinkPublisher;
use App\Infrastructure\Files\NativeAtomicSymlinkPublisher;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Processes\NativeProcessRunner;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Processes\ProcessRunner;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Str;

it('creates an idempotent Orbit root CA signed gateway leaf with DNS and IP identities', function (): void {
    $orbitHome = sys_get_temp_dir().'/orbit-gateway-certificate-'.Str::uuid();
    $caDirectory = $orbitHome.'/ca';
    mkdir(directory: $caDirectory, permissions: 0o700, recursive: true);
    $processes = new NativeProcessRunner;

    try {
        expect(
            $processes->run(new ProcessInvocation([
                'openssl',
                'genpkey',
                '-algorithm',
                'ED25519',
                '-out',
                $caDirectory.'/root.key',
            ]))->succeeded(),
        )->toBeTrue();
        expect(
            $processes->run(new ProcessInvocation([
                'openssl',
                'req',
                '-x509',
                '-new',
                '-key',
                $caDirectory.'/root.key',
                '-out',
                $caDirectory.'/root.pem',
                '-days',
                '3650',
                '-subj',
                '/CN=Orbit Root CA',
            ]))->succeeded(),
        )->toBeTrue();

        $issuer = new OpenSslGatewayCertificateIssuer(
            processes: $processes,
            validator: new OpenSslGatewayCertificateValidator($processes),
            links: new NativeAtomicSymlinkPublisher,
            orbitHome: $orbitHome,
        );
        $first = $issuer->issue('gateway.orbit', '10.44.0.1');
        $firstCertificate = file_get_contents($first->certificatePath);
        $firstSerial = gateway_certificate_serial($processes, $first->certificatePath);
        $firstExtensions = gateway_certificate_extensions($first->certificatePath);
        $firstText = gateway_certificate_text($processes, $first->certificatePath);
        $caddyValidation = gateway_certificate_caddy_validation(
            $processes,
            $orbitHome,
            $first->certificatePath,
            $first->privateKeyPath,
        );
        $second = $issuer->issue('gateway.orbit', '10.44.0.1');
        $secondCertificate = file_get_contents($second->certificatePath);
        $details = $processes->run(new ProcessInvocation([
            'openssl',
            'x509',
            '-in',
            $second->certificatePath,
            '-noout',
            '-issuer',
            '-subject',
            '-ext',
            'subjectAltName',
        ]));
        $updated = $issuer->issue('gateway.orbit', '10.44.0.2');
        $updatedDetails = $processes->run(new ProcessInvocation([
            'openssl',
            'x509',
            '-in',
            $updated->certificatePath,
            '-noout',
            '-ext',
            'subjectAltName',
        ]));

        expect($second)
            ->toEqual($first)
            ->and($secondCertificate)
            ->toBe($firstCertificate)
            ->and($details->succeeded())
            ->toBeTrue()
            ->and($details->stdout)
            ->toContain(
                'issuer=CN=Orbit Root CA',
                'subject=CN=gateway.orbit',
                'DNS:gateway.orbit',
                'IP Address:10.44.0.1',
            )
            ->and(gateway_certificate_validity_days($processes, $second->certificatePath))
            ->toBeIn([396, 397])
            ->and($firstExtensions['basicConstraints'] ?? null)
            ->toBe('CA:FALSE')
            ->and($firstExtensions['keyUsage'] ?? null)
            ->toBe('Digital Signature')
            ->and($firstExtensions['extendedKeyUsage'] ?? null)
            ->toBe('TLS Web Server Authentication')
            ->and($firstExtensions['subjectAltName'] ?? null)
            ->toBe('DNS:gateway.orbit, IP Address:10.44.0.1');
        expect($firstText)
            ->toContain('X509v3 Basic Constraints: critical', 'X509v3 Key Usage: critical');
        expect(str_contains($firstText, 'Key Encipherment'))
            ->toBeFalse();
        expect($caddyValidation->succeeded())
            ->toBeTrue()
            ->and(is_file($caDirectory.'/root.srl'))
            ->toBeFalse()
            ->and(fileperms($second->privateKeyPath) & 0o777)
            ->toBe(0o600)
            ->and(fileperms($second->certificatePath) & 0o777)
            ->toBe(0o644)
            ->and(file_get_contents($updated->certificatePath) === $firstCertificate)
            ->toBeFalse()
            ->and(gateway_certificate_serial($processes, $updated->certificatePath) === $firstSerial)
            ->toBeFalse()
            ->and($updatedDetails->stdout)
            ->toContain('IP Address:10.44.0.2');
        expect(str_contains($updatedDetails->stdout, 'IP Address:10.44.0.1'))
            ->toBeFalse();
    } finally {
        new Filesystem()->deleteDirectory($orbitHome);
    }
});

it('renews gateway leaves when they expire within 30 days', function (): void {
    $processes = new class implements ProcessRunner {
        /** @var list<ProcessInvocation> */
        public array $invocations = [];

        public function run(ProcessInvocation $invocation): CommandResult
        {
            $this->invocations[] = $invocation;

            return new CommandResult(0, 'PUBLIC KEY', '', 1, false);
        }
    };
    $validator = new OpenSslGatewayCertificateValidator($processes);
    $paths = new \App\Domain\Certificates\GatewayCertificatePaths('/tmp/gateway.key', '/tmp/gateway.pem');

    $validator->matches($paths, 'gateway.orbit', '10.44.0.1', '/tmp/root.pem');

    expect($processes->invocations)
        ->toContainEqual(new ProcessInvocation([
            'openssl',
            'x509',
            '-in',
            '/tmp/gateway.pem',
            '-noout',
            '-checkend',
            '2592000',
        ], timeout: 60.0));
});

it('rejects legacy gateway leaves whose lifetime exceeds 397 days', function (): void {
    $processes = new class implements ProcessRunner {
        public function run(ProcessInvocation $invocation): CommandResult
        {
            $stdout = in_array('-dates', $invocation->arguments, strict: true)
                ? "notBefore=Aug 25 00:00:00 2026 GMT\nnotAfter=Sep 27 00:00:01 2027 GMT\n"
                : 'PUBLIC KEY';

            return new CommandResult(0, $stdout, '', 1, false);
        }
    };
    $validator = new OpenSslGatewayCertificateValidator($processes);
    $paths = new \App\Domain\Certificates\GatewayCertificatePaths('/tmp/gateway.key', '/tmp/gateway.pem');

    expect($validator->matches($paths, 'gateway.orbit', '10.44.0.1', '/tmp/root.pem'))
        ->toBeFalse();
});

it('rejects gateway leaves with :invalidPolicy', function (string $extensions): void {
    $orbitHome = sys_get_temp_dir().'/orbit-gateway-certificate-policy-'.(string) Str::uuid();
    $caDirectory = $orbitHome.'/ca';
    $leafDirectory = $orbitHome.'/leaf';
    mkdir(directory: $caDirectory, permissions: 0o700, recursive: true);
    mkdir(directory: $leafDirectory, permissions: 0o700, recursive: true);
    $processes = new NativeProcessRunner;

    try {
        foreach ([
            ['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', $caDirectory.'/root.key'],
            [
                'openssl',
                'req',
                '-x509',
                '-new',
                '-key',
                $caDirectory.'/root.key',
                '-out',
                $caDirectory.'/root.pem',
                '-days',
                '3650',
                '-subj',
                '/CN=Orbit Root CA',
            ],
            ['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', $leafDirectory.'/gateway.key'],
            [
                'openssl',
                'req',
                '-new',
                '-key',
                $leafDirectory.'/gateway.key',
                '-out',
                $leafDirectory.'/gateway.csr',
                '-subj',
                '/CN=gateway.orbit',
            ],
        ] as $arguments) {
            expect($processes->run(new ProcessInvocation($arguments))->succeeded())->toBeTrue();
        }

        file_put_contents($leafDirectory.'/gateway.ext', $extensions);
        expect(
            $processes->run(new ProcessInvocation([
                'openssl',
                'x509',
                '-req',
                '-in',
                $leafDirectory.'/gateway.csr',
                '-CA',
                $caDirectory.'/root.pem',
                '-CAkey',
                $caDirectory.'/root.key',
                '-set_serial',
                '0x01',
                '-out',
                $leafDirectory.'/gateway.pem',
                '-days',
                '397',
                '-extfile',
                $leafDirectory.'/gateway.ext',
            ]))->succeeded(),
        )->toBeTrue();

        $paths = new \App\Domain\Certificates\GatewayCertificatePaths(
            $leafDirectory.'/gateway.key',
            $leafDirectory.'/gateway.pem',
        );

        expect(new OpenSslGatewayCertificateValidator($processes)->matches(
            $paths,
            'gateway.orbit',
            '10.44.0.1',
            $caDirectory.'/root.pem',
        ))->toBeFalse();
    } finally {
        new Filesystem()->deleteDirectory($orbitHome);
    }
})->with([
    'missing explicit leaf constraints and usages' => [
        'subjectAltName=DNS:gateway.orbit,IP:10.44.0.1',
    ],
    'an additional unapproved SAN' => [
        implode("\n", [
            'basicConstraints=critical,CA:FALSE',
            'keyUsage=critical,digitalSignature',
            'extendedKeyUsage=serverAuth',
            'subjectAltName=DNS:gateway.orbit,IP:10.44.0.1,DNS:other.orbit',
        ]),
    ],
    'legacy RSA key encipherment usage on an Ed25519 leaf' => [
        implode("\n", [
            'basicConstraints=critical,CA:FALSE',
            'keyUsage=critical,digitalSignature,keyEncipherment',
            'extendedKeyUsage=serverAuth',
            'subjectAltName=DNS:gateway.orbit,IP:10.44.0.1',
        ]),
    ],
    'non-critical leaf constraint' => [
        implode("\n", [
            'basicConstraints=CA:FALSE',
            'keyUsage=critical,digitalSignature',
            'extendedKeyUsage=serverAuth',
            'subjectAltName=DNS:gateway.orbit,IP:10.44.0.1',
        ]),
    ],
    'non-critical key usage' => [
        implode("\n", [
            'basicConstraints=critical,CA:FALSE',
            'keyUsage=digitalSignature',
            'extendedKeyUsage=serverAuth',
            'subjectAltName=DNS:gateway.orbit,IP:10.44.0.1',
        ]),
    ],
]);

it('rejects a gateway leaf with an RSA key pair and the exact approved policy', function (): void {
    $orbitHome = sys_get_temp_dir().'/orbit-gateway-certificate-rsa-'.(string) Str::uuid();
    $caDirectory = $orbitHome.'/ca';
    $leafDirectory = $orbitHome.'/leaf';
    mkdir(directory: $caDirectory, permissions: 0o700, recursive: true);
    mkdir(directory: $leafDirectory, permissions: 0o700, recursive: true);
    $processes = new NativeProcessRunner;

    try {
        foreach ([
            ['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', $caDirectory.'/root.key'],
            [
                'openssl',
                'req',
                '-x509',
                '-new',
                '-key',
                $caDirectory.'/root.key',
                '-out',
                $caDirectory.'/root.pem',
                '-days',
                '3650',
                '-subj',
                '/CN=Orbit Root CA',
            ],
            [
                'openssl',
                'genpkey',
                '-algorithm',
                'RSA',
                '-pkeyopt',
                'rsa_keygen_bits:2048',
                '-out',
                $leafDirectory.'/gateway.key',
            ],
            [
                'openssl',
                'req',
                '-new',
                '-key',
                $leafDirectory.'/gateway.key',
                '-out',
                $leafDirectory.'/gateway.csr',
                '-subj',
                '/CN=gateway.orbit',
            ],
        ] as $arguments) {
            expect($processes->run(new ProcessInvocation($arguments))->succeeded())->toBeTrue();
        }

        file_put_contents($leafDirectory.'/gateway.ext', implode("\n", [
            'basicConstraints=critical,CA:FALSE',
            'keyUsage=critical,digitalSignature',
            'extendedKeyUsage=serverAuth',
            'subjectAltName=DNS:gateway.orbit,IP:10.44.0.1',
        ]));
        expect(
            $processes->run(new ProcessInvocation([
                'openssl',
                'x509',
                '-req',
                '-in',
                $leafDirectory.'/gateway.csr',
                '-CA',
                $caDirectory.'/root.pem',
                '-CAkey',
                $caDirectory.'/root.key',
                '-set_serial',
                '0x01',
                '-out',
                $leafDirectory.'/gateway.pem',
                '-days',
                '397',
                '-extfile',
                $leafDirectory.'/gateway.ext',
            ]))->succeeded(),
        )->toBeTrue();

        $paths = new \App\Domain\Certificates\GatewayCertificatePaths(
            $leafDirectory.'/gateway.key',
            $leafDirectory.'/gateway.pem',
        );

        expect(new OpenSslGatewayCertificateValidator($processes)->matches(
            $paths,
            'gateway.orbit',
            '10.44.0.1',
            $caDirectory.'/root.pem',
        ))->toBeFalse();
    } finally {
        new Filesystem()->deleteDirectory($orbitHome);
    }
});

it('rejects invalid certificate identities before invoking OpenSSL', function (
    string $hostname,
    string $address,
): void {
    $processes = new class implements ProcessRunner {
        public int $calls = 0;

        public function run(ProcessInvocation $invocation): CommandResult
        {
            $this->calls++;

            return new CommandResult(0, '', '', 1, false);
        }
    };
    $issuer = new OpenSslGatewayCertificateIssuer(
        processes: $processes,
        validator: new OpenSslGatewayCertificateValidator($processes),
        links: new NativeAtomicSymlinkPublisher,
        orbitHome: '/home/orbit/.orbit',
    );

    expect(fn () => $issuer->issue($hostname, $address))
        ->toThrow(InvalidArgumentException::class)
        ->and($processes->calls)
        ->toBe(0);
})->with([
    'invalid hostname' => ['gateway orbit', '10.44.0.1'],
    'invalid IP address' => ['gateway.orbit', '10.44.0.999'],
]);

it('preserves the current usable certificate pair when atomic publication fails', function (): void {
    $orbitHome = sys_get_temp_dir().'/orbit-gateway-certificate-'.Str::uuid();
    $caDirectory = $orbitHome.'/ca';
    mkdir(directory: $caDirectory, permissions: 0o700, recursive: true);
    $processes = new NativeProcessRunner;

    try {
        expect(
            $processes->run(new ProcessInvocation([
                'openssl',
                'genpkey',
                '-algorithm',
                'ED25519',
                '-out',
                $caDirectory.'/root.key',
            ]))->succeeded(),
        )->toBeTrue();
        expect(
            $processes->run(new ProcessInvocation([
                'openssl',
                'req',
                '-x509',
                '-new',
                '-key',
                $caDirectory.'/root.key',
                '-out',
                $caDirectory.'/root.pem',
                '-days',
                '3650',
                '-subj',
                '/CN=Orbit Root CA',
            ]))->succeeded(),
        )->toBeTrue();

        $issuer = new OpenSslGatewayCertificateIssuer(
            processes: $processes,
            validator: new OpenSslGatewayCertificateValidator($processes),
            links: new NativeAtomicSymlinkPublisher,
            orbitHome: $orbitHome,
        );
        $current = $issuer->issue('gateway.orbit', '10.44.0.1');
        $currentCertificate = file_get_contents($current->certificatePath);
        $failingLinks = new class implements AtomicSymlinkPublisher {
            public function publish(string $target, string $link): void
            {
                throw new \RuntimeException('simulated atomic link failure');
            }
        };
        $failingIssuer = new OpenSslGatewayCertificateIssuer(
            processes: $processes,
            validator: new OpenSslGatewayCertificateValidator($processes),
            links: $failingLinks,
            orbitHome: $orbitHome,
        );

        expect(fn () => $failingIssuer->issue('gateway.orbit', '10.44.0.2'))
            ->toThrow(function (\App\Domain\Nodes\NodeProvisioningException $exception): void {
                expect($exception->step)
                    ->toBe('gateway-certificate-publish')
                    ->and($exception->errorCode)
                    ->toBe('gateway.certificate_publish_failed');
            });

        $details = $processes->run(new ProcessInvocation([
            'openssl',
            'x509',
            '-in',
            $current->certificatePath,
            '-noout',
            '-ext',
            'subjectAltName',
        ]));
        $certificatePublicKey = $processes->run(new ProcessInvocation([
            'openssl',
            'x509',
            '-in',
            $current->certificatePath,
            '-pubkey',
            '-noout',
        ]));
        $privatePublicKey = $processes->run(new ProcessInvocation([
            'openssl',
            'pkey',
            '-in',
            $current->privateKeyPath,
            '-pubout',
        ]));

        expect(file_get_contents($current->certificatePath))
            ->toBe($currentCertificate)
            ->and($details->stdout)
            ->toContain('IP Address:10.44.0.1')
            ->not
            ->toContain('IP Address:10.44.0.2')
            ->and(trim($certificatePublicKey->stdout))
            ->toBe(trim($privatePublicKey->stdout));
    } finally {
        new Filesystem()->deleteDirectory($orbitHome);
    }
});

function gateway_certificate_serial(NativeProcessRunner $processes, string $certificatePath): string
{
    return trim($processes->run(new ProcessInvocation([
        'openssl',
        'x509',
        '-in',
        $certificatePath,
        '-noout',
        '-serial',
    ]))->stdout);
}

function gateway_certificate_validity_days(NativeProcessRunner $processes, string $certificatePath): int
{
    $dates = $processes->run(new ProcessInvocation([
        'openssl',
        'x509',
        '-in',
        $certificatePath,
        '-noout',
        '-dates',
    ]))->stdout;
    $notBefore = [];
    $notAfter = [];
    preg_match('/notBefore=(.+)/', $dates, $notBefore);
    preg_match('/notAfter=(.+)/', $dates, $notAfter);
    $startsAt = new DateTimeImmutable($notBefore[1]);
    $expiresAt = new DateTimeImmutable($notAfter[1]);
    $days = $startsAt->diff($expiresAt)->days;

    return is_int($days) ? $days : 0;
}

/** @return array<array-key, mixed> */
function gateway_certificate_extensions(string $certificatePath): array
{
    $certificate = file_get_contents($certificatePath);
    $details = is_string($certificate) ? openssl_x509_parse($certificate) : false;
    $extensions = is_array($details) ? $details['extensions'] : null;

    return is_array($extensions) ? $extensions : [];
}

function gateway_certificate_text(NativeProcessRunner $processes, string $certificatePath): string
{
    return $processes->run(new ProcessInvocation([
        'openssl',
        'x509',
        '-in',
        $certificatePath,
        '-noout',
        '-text',
    ]))->stdout;
}

function gateway_certificate_caddy_validation(
    NativeProcessRunner $processes,
    string $directory,
    string $certificatePath,
    string $privateKeyPath,
): CommandResult {
    $configurationPath = $directory.'/Caddyfile';
    file_put_contents($configurationPath, <<<CADDYFILE
        https://gateway.orbit {
            tls {$certificatePath} {$privateKeyPath}
            respond "ok"
        }
        CADDYFILE);

    return $processes->run(new ProcessInvocation([
        'caddy',
        'validate',
        '--config',
        $configurationPath,
        '--adapter',
        'caddyfile',
    ]));
}
