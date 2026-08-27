<?php

declare(strict_types=1);

use App\Domain\Tools\DebianVersionNormalizer;
use App\Domain\Tools\SemverVersionNormalizer;

it('normalizes strict and short semantic versions without accepting branches', function (
    string $raw,
    ?string $normalized,
): void {
    expect(new SemverVersionNormalizer()->normalize($raw))->toBe($normalized);
})->with([
    'full' => ['2.4.3', '2.4.3'],
    'leading v' => ['v2.4.3', '2.4.3'],
    'short' => ['2.4', '2.4.0'],
    'prerelease' => ['2.4.3-rc.1', '2.4.3-rc.1'],
    'build' => ['2.4.3+build.7', '2.4.3+build.7'],
    'branch' => ['dev-main', null],
    'wildcard' => ['2.x-dev', null],
    'leading-zero major' => ['02.4.3', null],
    'leading-zero minor' => ['2.04.3', null],
    'leading-zero patch' => ['2.4.03', null],
    'leading-zero numeric prerelease' => ['2.4.3-01', null],
    'multiple leading v' => ['vv2.4.3', null],
    'control character' => ["2.4.3\n", null],
    'too long' => [str_repeat(string: '1', times: 256), null],
]);

it('normalizes only safely recognizable Debian upstream versions', function (
    string $raw,
    ?string $normalized,
): void {
    expect(new DebianVersionNormalizer(new SemverVersionNormalizer)->normalize($raw))->toBe($normalized);
})->with([
    'revision' => ['2.4.3-1ubuntu2', '2.4.3'],
    'epoch and revision' => ['1:2.4.3-1', '2.4.3'],
    'short upstream' => ['2.4-1', '2.4.0'],
    'tilde prerelease' => ['2.4.3~rc1-1', null],
    'ubuntu style upstream' => ['8.2+93ubuntu1', null],
    'invalid epoch' => ['x:2.4.3-1', null],
]);
