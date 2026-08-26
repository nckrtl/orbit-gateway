<?php

declare(strict_types=1);

namespace App\Domain\SourceControl;

use InvalidArgumentException;
use SensitiveParameter;

/** @mago-expect lint:cyclomatic-complexity Each branch rejects one unsafe Git origin shape. */
final class GitRepositoryOrigin
{
    public static function validate(#[SensitiveParameter] string $repository): string
    {
        if (! self::isValid($repository)) {
            throw new InvalidArgumentException('The Git repository origin is invalid.');
        }

        return $repository;
    }

    public static function isValid(#[SensitiveParameter] string $repository): bool
    {
        if (preg_match('//u', $repository) !== 1) {
            return false;
        }

        if ($repository === '' || preg_match('/[\p{Z}\p{C}]/u', $repository) !== 0) {
            return false;
        }

        if (preg_match('/\Agit@[^:\s?#]+:[^\s?#]+\z/u', $repository) === 1) {
            return true;
        }

        return self::isValidTransportUrl($repository);
    }

    private static function isValidTransportUrl(string $repository): bool
    {
        $parts = parse_url($repository);

        if (! is_array($parts)) {
            return false;
        }

        /** @var array<string, mixed> $parts */
        $scheme = is_string($parts['scheme'] ?? null) ? $parts['scheme'] : null;
        $host = is_string($parts['host'] ?? null) ? $parts['host'] : null;
        $path = is_string($parts['path'] ?? null) ? $parts['path'] : null;

        if (! is_string($host) || $host === '' || ! is_string($path) || $path === '') {
            return false;
        }

        if (array_key_exists('query', $parts) || array_key_exists('fragment', $parts)) {
            return false;
        }

        if ($scheme === 'https') {
            return ! array_key_exists('user', $parts) && ! array_key_exists('pass', $parts);
        }

        if ($scheme === 'ssh') {
            return ! array_key_exists('pass', $parts);
        }

        return false;
    }
}
