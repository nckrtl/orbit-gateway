<?php

declare(strict_types=1);

it('keeps Pest files out of Composer optimized classmaps', function (): void {
    $composer = json_decode(
        json: (string) file_get_contents(dirname(path: __DIR__, levels: 3).'/composer.json'),
        associative: true,
        flags: JSON_THROW_ON_ERROR,
    );

    expect($composer['autoload-dev']['exclude-from-classmap'] ?? [])
        ->toContain('/tests/');
});
