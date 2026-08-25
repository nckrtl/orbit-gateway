<?php

declare(strict_types=1);

namespace App\Infrastructure\Activity;

use Illuminate\Support\Str;

final readonly class CommandActivityInputSanitizer
{
    /** @mago-expect analysis:mixed-assignment Recursive request data has a mixed value boundary. */
    public function sanitize(mixed $value, ?string $key = null): mixed
    {
        if (is_string($key) && $this->isSensitiveKey($key)) {
            return '[REDACTED]';
        }

        if (! is_array($value)) {
            return is_string($value) ? $this->redactText($value) : $value;
        }

        $sanitized = [];

        foreach ($value as $nestedKey => $nestedValue) {
            $sanitized[$nestedKey] = $this->sanitize(
                $nestedValue,
                is_string($nestedKey) ? $nestedKey : null,
            );
        }

        return $sanitized;
    }

    public function redactText(string $value): string
    {
        $withoutUrlCredentials = preg_replace(
            pattern: '/\b([a-z][a-z0-9+.-]*:\/\/)[^\/@\s]+@/i',
            replacement: '$1[REDACTED]@',
            subject: $value,
        );
        $redacted = preg_replace(
            pattern: '/(password|token|secret|private[_ -]?key)(\s*[=:]\s*)\S+/i',
            replacement: '$1$2[REDACTED]',
            subject: is_string($withoutUrlCredentials) ? $withoutUrlCredentials : '',
        );

        return is_string($redacted) ? $redacted : '';
    }

    private function isSensitiveKey(string $key): bool
    {
        return (
            preg_match(
                '/(?:^|_)(?:password|token|secret|private_key)(?:_|$)/',
                Str::snake($key),
            ) === 1
        );
    }
}
