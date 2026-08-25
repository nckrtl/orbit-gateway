<?php

declare(strict_types=1);

use App\Infrastructure\Certificates\OpenSslLeafCertificateSigner;
use App\Infrastructure\Processes\NativeProcessRunner;
use App\Infrastructure\Processes\ProcessInvocation;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Str;

it('signs a target CSR for only the gateway-approved hostname', function (): void {
    $orbitHome = sys_get_temp_dir().'/orbit-leaf-signer-'.Str::uuid();
    $ca = "{$orbitHome}/ca";
    $target = "{$orbitHome}/target";
    mkdir(directory: $ca, permissions: 0o700, recursive: true);
    mkdir(directory: $target, permissions: 0o700, recursive: true);
    $processes = new NativeProcessRunner;

    try {
        expect(
            $processes->run(new ProcessInvocation([
                'openssl',
                'genpkey',
                '-algorithm',
                'ED25519',
                '-out',
                "{$ca}/root.key",
            ]))->succeeded(),
        )->toBeTrue();
        expect(
            $processes->run(new ProcessInvocation([
                'openssl',
                'req',
                '-x509',
                '-new',
                '-key',
                "{$ca}/root.key",
                '-out',
                "{$ca}/root.pem",
                '-days',
                '1',
                '-subj',
                '/CN=Orbit Test Root',
            ]))->succeeded(),
        )->toBeTrue();
        expect(
            $processes->run(new ProcessInvocation([
                'openssl',
                'genpkey',
                '-algorithm',
                'ED25519',
                '-out',
                "{$target}/leaf.key",
            ]))->succeeded(),
        )->toBeTrue();
        expect(
            $processes->run(new ProcessInvocation([
                'openssl',
                'req',
                '-new',
                '-key',
                "{$target}/leaf.key",
                '-out',
                "{$target}/leaf.csr",
                '-subj',
                '/CN=evil.example',
                '-addext',
                'subjectAltName=DNS:evil.example',
            ]))->succeeded(),
        )->toBeTrue();
        $request = file_get_contents("{$target}/leaf.csr");
        expect($request)->toBeString();
        $certificate = new OpenSslLeafCertificateSigner($processes, $orbitHome)->sign(
            'dev.app-dev.orbit',
            $request,
        );
        file_put_contents("{$target}/leaf.pem", $certificate);
        $approvedHost = $processes->run(new ProcessInvocation([
            'openssl',
            'x509',
            '-in',
            "{$target}/leaf.pem",
            '-noout',
            '-checkhost',
            'dev.app-dev.orbit',
        ]));
        $unapprovedHost = $processes->run(new ProcessInvocation([
            'openssl',
            'x509',
            '-in',
            "{$target}/leaf.pem",
            '-noout',
            '-checkhost',
            'evil.example',
        ]));
        $verified = $processes->run(new ProcessInvocation([
            'openssl',
            'verify',
            '-CAfile',
            "{$ca}/root.pem",
            "{$target}/leaf.pem",
        ]));

        expect($approvedHost->succeeded())
            ->toBeTrue()
            ->and($unapprovedHost->succeeded())
            ->toBeFalse()
            ->and($verified->succeeded())
            ->toBeTrue();
    } finally {
        new Filesystem()->deleteDirectory($orbitHome);
    }
});
