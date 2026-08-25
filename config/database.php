<?php

declare(strict_types=1);

$configuredHome = env('ORBIT_HOME');
$userHome = getenv('HOME');
$orbitHome = is_string($configuredHome) && $configuredHome !== ''
    ? $configuredHome
    : (is_string($userHome) && $userHome !== '' ? $userHome.'/.orbit' : base_path('.orbit'));

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
            'foreign_key_constraints' => env('DB_FOREIGN_KEYS', true),
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
