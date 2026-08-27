<?php

declare(strict_types=1);

use App\Domain\Tools\VersionConstraint;

it('validates nullable Composer Semver constraints', function (?string $constraint, bool $valid): void {
    expect(new VersionConstraint()->isValid($constraint))->toBe($valid);
})->with([
    'unrestricted' => [null, true],
    'caret' => ['^2.4', true],
    'compound' => ['>=2.4 <3.0', true],
    'empty' => ['', false],
    'control character' => ["^2.4\n", false],
    'too long' => [str_repeat(string: '1', times: 256), false],
    'garbage' => ['definitely-not-semver', false],
]);

it('checks a normalized candidate against the stored constraint', function (): void {
    $policy = new VersionConstraint;

    expect($policy->allows('2.4.9', '^2.4'))->toBeTrue()->and($policy->allows('3.0.0', '^2.4'))->toBeFalse();
});
