<?php

declare(strict_types=1);

$configuredHome = env('ORBIT_HOME');
$userHome = getenv('HOME');
$orbitHome = base_path('.orbit');

if (is_string($userHome) && $userHome !== '') {
    $orbitHome = $userHome.'/.orbit';
}

if (is_string($configuredHome) && $configuredHome !== '') {
    $orbitHome = $configuredHome;
}
$supportedPhpVersions = array_values(array_filter(
    explode(',', (string) env(key: 'ORBIT_SUPPORTED_PHP_VERSIONS', default: '8.4,8.5')),
    static fn (string $version): bool => $version !== '',
));

return [
    'home' => rtrim(string: $orbitHome, characters: '/'),
    'gateway_checkout' => rtrim(
        string: env(key: 'ORBIT_GATEWAY_CHECKOUT', default: '/home/orbit/orbit-gateway'),
        characters: '/',
    ),
    'app_dev_domain' => trim(
        string: env(key: 'ORBIT_APP_DEV_DOMAIN', default: 'orbit'),
        characters: '.',
    ),
    'supported_php_versions' => $supportedPhpVersions,
    'command_timeout' => 900.0,
];
