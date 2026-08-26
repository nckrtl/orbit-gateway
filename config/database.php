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

$configuredDatabase = env('DB_DATABASE');
$database = is_string($configuredDatabase) && $configuredDatabase !== ''
    ? $configuredDatabase
    : rtrim(string: $orbitHome, characters: '/').'/gateway.sqlite';

return [
    'default' => 'sqlite',

    'connections' => [
        'sqlite' => [
            'driver' => 'sqlite',
            'url' => env('DB_URL'),
            'database' => $database,
            'prefix' => '',
            'foreign_key_constraints' => env(key: 'DB_FOREIGN_KEYS', default: true),
            'busy_timeout' => 5_000,
            'journal_mode' => 'WAL',
            'synchronous' => 'NORMAL',
            'transaction_mode' => 'IMMEDIATE',
        ],
    ],

    'migrations' => [
        'table' => 'migrations',
        'update_date_on_publish' => true,
    ],
];
