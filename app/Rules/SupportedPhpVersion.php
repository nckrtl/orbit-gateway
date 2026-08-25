<?php

declare(strict_types=1);

namespace App\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Support\Facades\Config;

final readonly class SupportedPhpVersion implements ValidationRule
{
    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (is_string($value) && in_array($value, self::all(), strict: true)) {
            return;
        }

        $fail('The selected PHP version is not supported.');
    }

    /** @return non-empty-list<string> */
    public static function all(): array
    {
        $versions = array_values(array_filter(
            array_map(
                static fn (mixed $version): string => is_string($version) ? $version : '',
                Config::array('orbit.supported_php_versions'),
            ),
            static fn (string $version): bool => $version !== '',
        ));

        return $versions === [] ? ['8.4', '8.5'] : $versions;
    }
}
