<?php

declare(strict_types=1);

namespace App\Infrastructure\Activity;

use Illuminate\Support\Str;

final readonly class CommandActivityInputSanitizer
{
    private const string REDACTED = '[REDACTED]';

    /** @var list<string> */
    private const array FORBIDDEN_KEYS = [
        'app_key',
        'appkey',
        'application_key',
        'operation_token',
        'executor_secret',
        'password',
        'password_hash',
        'secret',
        'token',
        'api_key',
        'api_token',
        'access_token',
        'refresh_token',
        'private_key',
        'pre_shared_key',
        'bearer',
        'bearer_token',
    ];

    private const string SECRET_KEY_CORE =
        '(?:APP[_-]?KEY|APPLICATION[_-]?KEY|APPKEY|API[_-]?KEY|API[_-]?TOKEN|ACCESS[_-]?TOKEN|'
            .'REFRESH[_-]?TOKEN|OPERATION[_-]?TOKEN|EXECUTOR[_-]?SECRET|PRIVATE[_-]?KEY|'
            .'PRE[_-]?SHARED[_-]?KEY|PASSWORD[_-]?HASH|PASSWORD|SECRET|TOKEN|BEARER[_-]?TOKEN|BEARER)';

    private const string SECRET_KEY_IDENTIFIER = '(?:[A-Za-z][A-Za-z0-9]*[_-])*'.self::SECRET_KEY_CORE;

    private const string PEM_BLOCK_PATTERN = '/-----BEGIN [A-Z0-9 ]+-----[\s\S]*?-----END [A-Z0-9 ]+-----/';

    /** @mago-expect analysis:mixed-assignment Recursive request data has a mixed value boundary. */
    public function sanitize(mixed $value, ?string $key = null): mixed
    {
        if (is_string($key) && $this->isSensitiveKey($key)) {
            return self::REDACTED;
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
        $redacted =
            preg_replace(
                pattern: self::PEM_BLOCK_PATTERN,
                replacement: self::REDACTED,
                subject: $value,
            ) ?? $value;
        $redacted =
            preg_replace(
                pattern: '/\b([a-z][a-z0-9+.-]*:\/\/)[^\/@\s]+@/i',
                replacement: '$1'.self::REDACTED.'@',
                subject: $redacted,
            ) ?? $redacted;
        $redacted =
            preg_replace(
                pattern: '/\b((?:Proxy-)?Authorization)\s*:\s*[^\s\'\"]+(?:\s+[^\s\'\"]+)?/i',
                replacement: '$1: '.self::REDACTED,
                subject: $redacted,
            ) ?? $redacted;
        $redacted =
            preg_replace(
                pattern: '/\bBearer\s+(?:"[^"]*"|\'[^\']*\'|[A-Za-z0-9][A-Za-z0-9._\-+\/=]{7,})/i',
                replacement: 'Bearer '.self::REDACTED,
                subject: $redacted,
            ) ?? $redacted;
        $keys = self::SECRET_KEY_IDENTIFIER;
        $redacted =
            preg_replace(
                pattern: '/\b('.$keys.')\s*=\s*(?:"[^"]*"|\'[^\']*\'|\S+)/i',
                replacement: '$1='.self::REDACTED,
                subject: $redacted,
            ) ?? $redacted;
        $redacted =
            preg_replace(
                pattern: '/("(?:'.$keys.')"\s*:\s*)(?:"(?:\\\\.|[^"\\\\])*"|\'(?:\\\\.|[^\'\\\\])*\'|[^,}\s]+)/i',
                replacement: '$1"'.self::REDACTED.'"',
                subject: $redacted,
            ) ?? $redacted;

        return (
            preg_replace(
                pattern: '/\b('.$keys.')\s*:\s*(?:"[^"]*"|\'[^\']*\'|\S+)/i',
                replacement: '$1: '.self::REDACTED,
                subject: $redacted,
            ) ?? $redacted
        );
    }

    private function isSensitiveKey(string $key): bool
    {
        $underscored = str_replace(search: '-', replace: '_', subject: $key);
        $normalized = preg_match('/\A[A-Z0-9_]+\z/D', $underscored) === 1
            ? strtolower($underscored)
            : Str::snake($underscored);

        if (in_array($normalized, self::FORBIDDEN_KEYS, strict: true)) {
            return true;
        }

        return (
            preg_match(
                '/(?:^|_)(app_?key|password(?:_hash)?|secret|token|api_?key|api_?token|access_?token|refresh_?token|private_?key|pre_?shared_?key|bearer(?:_?token)?)$/',
                $normalized,
            ) === 1
        );
    }
}
