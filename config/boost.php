<?php

declare(strict_types=1);

return [
    'rules' => [
        'enabled' => true,
        'scoped_guidelines' => true,
    ],

    'guidelines' => [
        'exclude' => [
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
