<?php

declare(strict_types=1);

namespace App\Http\Requests\Nodes;

use App\Data\Nodes\MacOsAppDevSetupResultData;
use App\Infrastructure\Activity\CommandActivityInputSanitizer;
use App\Infrastructure\Http\TopLevelJsonObjectInspector;
use Closure;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\ValidationException;
use InvalidArgumentException;
use JsonException;

final class MacOsAppDevSetupResultRequest extends FormRequest
{
    protected function prepareForValidation(): void
    {
        try {
            app(TopLevelJsonObjectInspector::class)->inspect(
                $this->getContent(),
                ['exit_code', 'diagnostics'],
            );
        } catch (InvalidArgumentException) {
            throw ValidationException::withMessages([
                'body' => ['The request body must be a JSON object with unique allowed keys.'],
            ]);
        }
    }

    /**
     * @return array<array-key, mixed>
     *
     * @mago-expect analysis:mixed-assignment JSON decoding is checked before the value enters validation data.
     */
    public function validationData(): array
    {
        $data = parent::validationData();

        try {
            $decoded = json_decode($this->getContent(), associative: true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return $data;
        }

        if (is_array($decoded) && array_key_exists('diagnostics', $decoded)) {
            $data['diagnostics'] = $decoded['diagnostics'];
        }

        return $data;
    }

    /** @return array<string, list<mixed>> */
    public function rules(): array
    {
        return [
            'exit_code' => [
                'required',
                static function (string $attribute, mixed $value, Closure $fail): void {
                    if (! is_int($value)) {
                        $fail("The {$attribute} field must be an integer.");
                    }
                },
                'between:0,255',
            ],
            'diagnostics' => [
                'present',
                'string',
                static function (string $attribute, mixed $value, Closure $fail): void {
                    if (! is_string($value) || strlen($value) > 32_768) {
                        $fail("The {$attribute} field must not exceed 32768 bytes.");
                    }
                },
            ],
        ];
    }

    /** @mago-expect analysis:mixed-assignment Validated diagnostics are asserted before sanitization. */
    public function result(): MacOsAppDevSetupResultData
    {
        $validatedDiagnostics = $this->validated('diagnostics');
        assert(
            is_string($validatedDiagnostics),
            description: 'Validated diagnostics must be a string.',
        );
        $diagnostics = app(CommandActivityInputSanitizer::class)->sanitizeDiagnostics($validatedDiagnostics);

        return new MacOsAppDevSetupResultData(
            exitCode: $this->integer('exit_code'),
            diagnostics: $diagnostics,
        );
    }
}
