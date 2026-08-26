<?php

declare(strict_types=1);

use App\Domain\Certificates\LeafCertificateSigner;
use App\Infrastructure\Certificates\OpenSslLeafCertificateSigner;
use App\Infrastructure\Processes\NativeProcessRunner;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Models\Activity;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Str;

it('returns only the current public root CA with request correlation', function (): void {
    [$directory, , $certificate] = root_ca_endpoint_certificate();
    $requestId = (string) Str::uuid();
    app()->instance(LeafCertificateSigner::class, new class($certificate) implements LeafCertificateSigner {
        public function __construct(
            private readonly string $certificate,
        ) {}

        public function sign(string $hostname, string $certificateRequest): string
        {
            throw new LogicException('Signing is outside the root CA endpoint.');
        }

        public function rootCertificate(): string
        {
            return $this->certificate;
        }
    });

    try {
        $response = $this
            ->withHeader('X-Orbit-Request-Id', $requestId)
            ->getJson('/api/v1/ca/root');

        $response
            ->assertOk()
            ->assertHeader('X-Orbit-Request-Id', $requestId)
            ->assertExactJson([
                'data' => [
                    'root_ca' => $certificate,
                    'sha256' => openssl_x509_fingerprint($certificate, digest_algo: 'sha256'),
                ],
                'meta' => ['request_id' => $requestId],
            ]);

        expect($response->getContent())
            ->not->toContain('PRIVATE KEY')->and(Activity::query()->sole()->properties?->toJson())
            ->not->toContain('BEGIN CERTIFICATE');
    } finally {
        new Filesystem()->deleteDirectory($directory);
    }
});

it('does not serve an expired root CA', function (): void {
    [$directory, $orbitHome] = root_ca_endpoint_certificate();
    $invalidRequestId = 'not-a-uuid';
    app()->instance(LeafCertificateSigner::class, new OpenSslLeafCertificateSigner(
        new NativeProcessRunner,
        $orbitHome,
        static fn (): int => PHP_INT_MAX,
    ));

    try {
        $response = $this
            ->withHeader('X-Orbit-Request-Id', $invalidRequestId)
            ->getJson('/api/v1/ca/root')
            ->assertServiceUnavailable()
            ->assertJsonPath('error.code', 'ca.unavailable')
            ->assertJsonPath('error.message', 'Gateway root CA is unavailable.')
            ->assertJsonPath('error.details', []);

        $requestId = $response->headers->get('X-Orbit-Request-Id');

        expect($requestId)
            ->toBeString()
            ->not
            ->toBe($invalidRequestId)
            ->and(Str::isUuid($requestId))
            ->toBeTrue();
    } finally {
        new Filesystem()->deleteDirectory($directory);
    }
});

it('returns 503 with a bounded error when the root CA is unavailable', function (): void {
    $requestId = 'c5d56319-b820-440c-a7c5-f6bf8b6bf310';
    app()->instance(LeafCertificateSigner::class, new class implements LeafCertificateSigner {
        public function sign(string $hostname, string $certificateRequest): string
        {
            throw new LogicException('Signing is outside the root CA endpoint.');
        }

        public function rootCertificate(): string
        {
            throw new RuntimeException('/home/orbit/.orbit/ca/root.key is missing.');
        }
    });

    $response = $this
        ->withHeader('X-Orbit-Request-Id', $requestId)
        ->getJson('/api/v1/ca/root');

    $response
        ->assertServiceUnavailable()
        ->assertHeader('X-Orbit-Request-Id', $requestId)
        ->assertJsonPath('error.code', 'ca.unavailable')
        ->assertJsonPath('error.message', 'Gateway root CA is unavailable.')
        ->assertJsonPath('error.details', []);

    expect($response->getContent())
        ->not->toContain('/home/orbit')
        ->not->toContain('root.key');
});

/** @return array{string, string, string} */
function root_ca_endpoint_certificate(): array
{
    $directory = sys_get_temp_dir().'/orbit-root-ca-endpoint-'.Str::uuid();
    $orbitHome = $directory.'/orbit';
    $ca = $orbitHome.'/ca';
    mkdir(directory: $ca, permissions: 0o700, recursive: true);
    $processes = new NativeProcessRunner;
    $key = $ca.'/root.key';
    $certificate = $ca.'/root.pem';
    $keyResult = $processes->run(new ProcessInvocation([
        'openssl',
        'genpkey',
        '-algorithm',
        'ED25519',
        '-out',
        $key,
    ]));
    $certificateResult = $processes->run(new ProcessInvocation([
        'openssl',
        'req',
        '-x509',
        '-new',
        '-key',
        $key,
        '-out',
        $certificate,
        '-days',
        '1',
        '-subj',
        '/CN=Orbit Test Root CA',
    ]));

    if (! $keyResult->succeeded() || ! $certificateResult->succeeded()) {
        throw new RuntimeException('Could not create the endpoint root CA test fixture.');
    }

    return [$directory, $orbitHome, (string) file_get_contents($certificate)];
}
