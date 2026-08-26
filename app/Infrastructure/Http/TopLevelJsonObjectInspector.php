<?php

declare(strict_types=1);

namespace App\Infrastructure\Http;

use InvalidArgumentException;
use JsonException;

/**
 * @mago-expect lint:cyclomatic-complexity The small lexer must traverse each JSON grammar branch.
 * @mago-expect lint:kan-defect The small lexer must traverse each JSON grammar branch.
 * @mago-expect lint:too-many-methods Each JSON grammar token has one focused parser method.
 */
final class TopLevelJsonObjectInspector
{
    /**
     * @param list<string> $allowedKeys
     * @return list<string>
     */
    public function inspect(string $json, array $allowedKeys): array
    {
        $offset = 0;
        /** @var list<string> $keys */
        $keys = $this->parseObject($json, $offset, $allowedKeys);
        $this->skipWhitespace($json, $offset);

        if ($offset !== strlen($json)) {
            throw $this->invalid();
        }

        return $keys;
    }

    /**
     * @param list<string>|null $allowedKeys
     * @return list<string>
     */
    /** @mago-expect lint:halstead The object parser enforces ordered JSON delimiters and unique allowed keys. */
    private function parseObject(string $json, int &$offset, ?array $allowedKeys = null): array
    {
        $this->expect($json, $offset, '{');
        $this->skipWhitespace($json, $offset);
        /** @var list<string> $keys */
        $keys = [];

        if ($this->consume($json, $offset, '}')) {
            return $keys;
        }

        while (true) {
            $key = $this->parseString($json, $offset);

            if ($allowedKeys !== null) {
                if (in_array($key, $keys, strict: true) || ! in_array($key, $allowedKeys, strict: true)) {
                    throw $this->invalid();
                }

                $keys[] = $key;
            }

            $this->skipWhitespace($json, $offset);
            $this->expect($json, $offset, ':');
            $this->parseValue($json, $offset);
            $this->skipWhitespace($json, $offset);

            if ($this->consume($json, $offset, '}')) {
                return $keys;
            }

            $this->expect($json, $offset, ',');
            $this->skipWhitespace($json, $offset);
        }
    }

    private function parseValue(string $json, int &$offset): void
    {
        $this->skipWhitespace($json, $offset);

        if ($offset >= strlen($json)) {
            throw $this->invalid();
        }

        $character = $json[$offset];

        match ($character) {
            '"' => $this->parseString($json, $offset),
            '{' => $this->parseObject($json, $offset),
            '[' => $this->parseArray($json, $offset),
            't' => $this->parseLiteral($json, $offset, 'true'),
            'f' => $this->parseLiteral($json, $offset, 'false'),
            'n' => $this->parseLiteral($json, $offset, 'null'),
            default => $this->parseNumber($json, $offset),
        };
    }

    private function parseArray(string $json, int &$offset): void
    {
        $this->expect($json, $offset, '[');
        $this->skipWhitespace($json, $offset);

        if ($this->consume($json, $offset, ']')) {
            return;
        }

        while (true) {
            $this->parseValue($json, $offset);
            $this->skipWhitespace($json, $offset);

            if ($this->consume($json, $offset, ']')) {
                return;
            }

            $this->expect($json, $offset, ',');
        }
    }

    /** @mago-expect analysis:mixed-assignment Decoded JSON strings are checked before return. */
    private function parseString(string $json, int &$offset): string
    {
        $start = $offset;
        $this->expect($json, $offset, '"');
        $length = strlen($json);

        while ($offset < $length) {
            $character = $json[$offset++];

            if ($character === '"') {
                $encoded = substr($json, $start, $offset - $start);

                try {
                    $decoded = json_decode($encoded, associative: false, flags: JSON_THROW_ON_ERROR);
                } catch (JsonException) {
                    throw $this->invalid();
                }

                if (! is_string($decoded)) {
                    throw $this->invalid();
                }

                return $decoded;
            }

            if (ord($character[0]) < 0x20) {
                throw $this->invalid();
            }

            if ($character !== '\\') {
                continue;
            }

            if ($offset >= $length) {
                throw $this->invalid();
            }

            $escape = $json[$offset++];

            if ($escape === 'u') {
                $hex = substr(string: $json, offset: $offset, length: 4);

                if (strlen($hex) !== 4 || preg_match('/\A[0-9a-fA-F]{4}\z/D', $hex) !== 1) {
                    throw $this->invalid();
                }

                $offset += 4;

                continue;
            }

            if (! in_array(needle: $escape, haystack: ['"', '\\', '/', 'b', 'f', 'n', 'r', 't'], strict: true)) {
                throw $this->invalid();
            }
        }

        throw $this->invalid();
    }

    private function parseNumber(string $json, int &$offset): void
    {
        $remaining = substr($json, $offset);
        $matches = [];

        if (preg_match('/\A-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/D', $remaining, $matches) !== 1) {
            throw $this->invalid();
        }

        $offset += strlen($matches[0]);
    }

    private function parseLiteral(string $json, int &$offset, string $literal): void
    {
        if (substr($json, $offset, strlen($literal)) !== $literal) {
            throw $this->invalid();
        }

        $offset += strlen($literal);
    }

    private function expect(string $json, int &$offset, string $expected): void
    {
        $this->skipWhitespace($json, $offset);

        if (! $this->consume($json, $offset, $expected)) {
            throw $this->invalid();
        }
    }

    private function consume(string $json, int &$offset, string $expected): bool
    {
        if (($json[$offset] ?? null) !== $expected) {
            return false;
        }

        $offset++;

        return true;
    }

    private function skipWhitespace(string $json, int &$offset): void
    {
        $length = strlen($json);

        while ($offset < $length && str_contains(" \t\r\n", $json[$offset])) {
            $offset++;
        }
    }

    private function invalid(): InvalidArgumentException
    {
        return new InvalidArgumentException('The request body must be a JSON object with unique allowed keys.');
    }
}
