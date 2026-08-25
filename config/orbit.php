<?php

declare(strict_types=1);

$configuredHome = env('ORBIT_HOME');
$userHome = getenv('HOME');
$orbitHome = is_string($configuredHome) && $configuredHome !== ''
    ? $configuredHome
    : (is_string($userHome) && $userHome !== '' ? $userHome.'/.orbit' : base_path('.orbit'));
$supportedPhpVersions = array_values(array_filter(
    explode(',', (string) env('ORBIT_SUPPORTED_PHP_VERSIONS', '8.4,8.5')),
    static fn (string $version): bool => $version !== '',
));

return [
    'home' => rtrim(string: $orbitHome, characters: '/'),
    'gateway_checkout' => rtrim(
        string: env('ORBIT_GATEWAY_CHECKOUT', '/home/orbit/orbit-gateway'),
        characters: '/',
    ),
    'app_dev_domain' => trim(string: env('ORBIT_APP_DEV_DOMAIN', 'orbit'), characters: '.'),
    'supported_php_versions' => $supportedPhpVersions,
    'command_timeout' => 900.0,
];
