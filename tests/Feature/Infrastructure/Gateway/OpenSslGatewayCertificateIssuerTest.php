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
            ->and(fileperms($second->privateKeyPath) & 0o777)
            ->toBe(0o600)
            ->and(fileperms($second->certificatePath) & 0o777)
            ->toBe(0o644)
            ->and(file_get_contents($updated->certificatePath))
            ->not->toBe($firstCertificate)->and($updatedDetails->stdout)->toContain('IP Address:10.44.0.2')
            ->not->toContain('IP Address:10.44.0.1');
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
