<?php

declare(strict_types=1);

namespace App\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;

final readonly class SupportedPhpVersion implements ValidationRule
{
    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (self::isSupported($value)) {
            return;
        }

        $fail('The selected PHP version is not supported.');
    }

    public static function isSupported(mixed $value): bool
    {
        if (! is_string($value)) {
            return false;
        }

        if (preg_match('/\A(?:[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\z/D', $value) !== 1) {
            return false;
        }

        return version_compare(version1: $value, version2: '8.4', operator: '>=');
    }
}
