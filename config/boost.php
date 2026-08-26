<?php

declare(strict_types=1);

return [
    'enforce_tests' => true,

    'rules' => [
        'enabled' => true,
        'scoped_guidelines' => true,
    ],

    'guidelines' => [
        'exclude' => [
            'deployments',
            'spatie/guidelines-skills/core',
        ],
    ],
    'skills' => [
        'exclude' => [
            'infer-conventions',
            'spatie-javascript',
        ],
    ],
];
