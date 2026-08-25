<?php

declare(strict_types=1);

use App\Infrastructure\Ssh\HostKey;
use App\Infrastructure\Ssh\KnownHostsRepository;
use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Str;

it('installs and replaces pinned host keys atomically', function (): void {
    $directory = sys_get_temp_dir().'/orbit-known-hosts-'.Str::uuid();
    $path = $directory.'/ssh/known_hosts';
    $repository = new KnownHostsRepository($path);

    try {
        $repository->put('10.44.0.3', 22, new HostKey('ssh-ed25519', 'FIRST', 'SHA256:first'));
        $repository->put('10.44.0.3', 22, new HostKey('ssh-ed25519', 'SECOND', 'SHA256:second'));

        expect(file_get_contents($path))
            ->toBe("10.44.0.3 ssh-ed25519 SECOND\n")
            ->and(fileperms($path) & 0o777)
            ->toBe(0o600)
            ->and(fileperms(dirname($path)) & 0o777)
            ->toBe(0o700);
    } finally {
        new Filesystem()->deleteDirectory($directory);
    }
});
