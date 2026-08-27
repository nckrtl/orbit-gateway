<?php

declare(strict_types=1);

namespace App\Domain\Tools;

use Composer\Semver\Semver;
use Composer\Semver\VersionParser;
use UnexpectedValueException;

final readonly class VersionConstraint
{
    public function isValid(?string $constraint): bool
    {
        if ($constraint === null) {
            return true;
        }

        if (
            $constraint === ''
            || strlen($constraint) > 255
            || preg_match('/[\x00-\x1F\x7F]/', $constraint) === 1
        ) {
            return false;
        }

        try {
            new VersionParser()->parseConstraints($constraint);
        } catch (UnexpectedValueException) {
            return false;
        }

        return true;
    }

    public function allows(string $normalizedVersion, string $constraint): bool
    {
        return Semver::satisfies($normalizedVersion, $constraint);
    }
}
