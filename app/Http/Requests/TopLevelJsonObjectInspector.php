<?php

declare(strict_types=1);

namespace App\Http\Requests;

use JsonException;
use stdClass;
use UnexpectedValueException;

/** @mago-expect lint:cyclomatic-complexity The scanner validates one bounded top-level JSON grammar. */
final readonly class TopLevelJsonObjectInspector
{
    /**
     * @param list<string> $allowedKeys
     * @return array<string, mixed>
     * @throws UnexpectedValueException
     * @mago-expect analysis:mixed-assignment JSON decoding is an untyped transport boundary.
     */
    public function inspect(string $json, array $allowedKeys): array
    {
        if (trim($json) === '') {
            return [];
        }

        try {
            $object = json_decode($json, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            $this->fail('The request body must be a valid JSON object.');
        }

        if (! $object instanceof stdClass) {
            $this->fail('The request body must be a valid JSON object.');
        }

        $keys = $this->topLevelKeys($json);

        if (count($keys) !== count(array_unique($keys))) {
            $this->fail('The request body contains duplicate top-level keys.');
        }

        if (array_diff($keys, $allowedKeys) !== []) {
            $this->fail('The request body contains unsupported top-level keys.');
        }

        try {
            /** @var array<string, mixed> $payload */
            $payload = json_decode($json, associative: true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            $this->fail('The request body must be a valid JSON object.');
        }

        return $payload;
    }

    /**
     * @return list<string>
     * @mago-expect analysis:mixed-assignment JSON string decoding is an untyped transport boundary.
     */
    private function topLevelKeys(string $json): array
    {
        $keys = [];
        $length = strlen($json);
        $depth = 0;
        $expectsKey = false;

        for ($index = 0; $index < $length; $index++) {
            $character = $json[$index];

            if ($character === '{' || $character === '[') {
                $depth++;

                if ($depth === 1 && $character === '{') {
                    $expectsKey = true;
                }

                continue;
            }

            if ($character === '}' || $character === ']') {
                $depth--;

                continue;
            }

            if ($character === ',' && $depth === 1) {
                $expectsKey = true;

                continue;
            }

            if ($character !== '"') {
                continue;
            }

            $end = $this->stringEnd($json, $index + 1);

            if ($depth === 1 && $expectsKey) {
                $token = substr($json, $index, $end - $index + 1);

                try {
                    $key = json_decode($token, flags: JSON_THROW_ON_ERROR);
                } catch (JsonException) {
                    $this->fail('The request body must be a valid JSON object.');
                }

                if (! is_string($key)) {
                    $this->fail('The request body must be a valid JSON object.');
                }

                $keys[] = $key;
                $expectsKey = false;
            }

            $index = $end;
        }

        return $keys;
    }

    private function stringEnd(string $json, int $index): int
    {
        $length = strlen($json);
        $escaped = false;

        for (; $index < $length; $index++) {
            $character = $json[$index];

            if ($escaped) {
                $escaped = false;

                continue;
            }

            if ($character === '\\') {
                $escaped = true;

                continue;
            }

            if ($character === '"') {
                return $index;
            }
        }

        $this->fail('The request body must be a valid JSON object.');
    }

    /** @throws UnexpectedValueException */
    private function fail(string $message): never
    {
        throw new UnexpectedValueException($message);
    }
}
