<?php

declare(strict_types=1);

it('keeps known VPN setting keys inside the typed VPN settings boundary', function (): void {
    $appDirectory = dirname(path: __DIR__, levels: 3).'/app';
    $owner = $appDirectory.'/Domain/WireGuard/VpnSettings.php';
    $keys = [
        'vpn.subnet',
        'vpn.port',
        'vpn.endpoint',
        'vpn.dns_server',
        'vpn.domain',
        'vpn.private_interface',
    ];
    $violations = [];
    $files = new \RecursiveIteratorIterator(
        new \RecursiveDirectoryIterator($appDirectory, \FilesystemIterator::SKIP_DOTS),
    );

    foreach ($files as $file) {
        if (! $file instanceof \SplFileInfo || $file->getExtension() !== 'php' || $file->getPathname() === $owner) {
            continue;
        }

        $contents = file_get_contents($file->getPathname());

        if (! is_string($contents)) {
            continue;
        }

        foreach ($keys as $key) {
            if (! str_contains($contents, "'{$key}'") && ! str_contains($contents, "\"{$key}\"")) {
                continue;
            }

            $relativePath = str_replace(
                search: $appDirectory.'/',
                replace: '',
                subject: $file->getPathname(),
            );
            $violations[] = "{$relativePath}: {$key}";
        }
    }

    expect($violations)
        ->toBeEmpty()
        ->and(is_file($owner))
        ->toBeTrue();

    $method = new ReflectionMethod(App\Domain\WireGuard\VpnSettings::class, 'configuredDomain');

    expect((string) $method->getReturnType())
        ->toBe('?string')
        ->and($method->getNumberOfParameters())
        ->toBe(0);
});
