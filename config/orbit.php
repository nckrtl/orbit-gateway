<?php

declare(strict_types=1);

$configuredHome = env('ORBIT_HOME');
$userHome = getenv('HOME');
$orbitHome = is_string($configuredHome) && $configuredHome !== ''
    ? $configuredHome
    : (is_string($userHome) && $userHome !== '' ? $userHome.'/.orbit' : base_path('.orbit'));

return [
    'home' => rtrim(string: $orbitHome, characters: '/'),
];
