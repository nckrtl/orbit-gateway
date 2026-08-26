<?php

declare(strict_types=1);

use App\Rules\SupportedPhpVersion;
use Illuminate\Support\Facades\Validator;

it('accepts canonical PHP versions from 8.4 upward', function (string $version): void {
    $validator = Validator::make(
        ['php_version' => $version],
        ['php_version' => [new SupportedPhpVersion]],
    );

    expect($validator->passes())->toBeTrue();
})->with(['8.4', '8.5', '8.6', '9.0', '10.12']);

it('rejects noncanonical or older PHP versions', function (string $version): void {
    $validator = Validator::make(
        ['php_version' => $version],
        ['php_version' => [new SupportedPhpVersion]],
    );

    expect($validator->fails())->toBeTrue();
})->with([
    'below floor' => '8.3',
    'missing minor' => '8',
    'patch version' => '8.4.1',
    'leading zero' => '08.4',
    'alias' => 'latest',
    'leading whitespace' => ' 8.4',
    'trailing whitespace' => '8.4 ',
    'invalid UTF-8' => "\xC3\x28",
    'shell syntax' => '8.5;id',
]);
