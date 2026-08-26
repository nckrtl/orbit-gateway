<?php

declare(strict_types=1);

namespace App\Http\Requests\Nodes;

use App\Data\Nodes\MacOsAppDevSetupFactsData;
use App\Infrastructure\Http\TopLevelJsonObjectInspector;
use App\Models\Node;
use Closure;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;
use InvalidArgumentException;

final class MacOsAppDevSetupScriptRequest extends FormRequest
{
    protected function prepareForValidation(): void
    {
        try {
            app(TopLevelJsonObjectInspector::class)->inspect(
                $this->getContent(),
                ['platform', 'architecture', 'username', 'home_directory'],
            );
        } catch (InvalidArgumentException) {
            throw ValidationException::withMessages([
                'body' => ['The request body must be a JSON object with unique allowed keys.'],
            ]);
        }
    }

    /**
     * @return array<string, list<mixed>>
     *
     * @mago-expect analysis:mixed-assignment Form Request users and rule values are untyped transport boundaries.
     */
    public function rules(): array
    {
        return [
            'platform' => ['required', 'string', Rule::in(['darwin'])],
            'architecture' => [
                'required',
                'string',
                'regex:/\A[A-Za-z0-9_.-]{1,64}\z/D',
                function (string $attribute, mixed $value, Closure $fail): void {
                    $node = $this->user();

                    if (! $node instanceof Node || $value !== $node->architecture) {
                        $fail("The {$attribute} field does not match the registered node identity.");
                    }
                },
            ],
            'username' => [
                'required',
                'string',
                'regex:/\A[a-z_][a-z0-9_-]{0,63}\z/D',
                function (string $attribute, mixed $value, Closure $fail): void {
                    $node = $this->user();

                    if (! $node instanceof Node || $value !== $node->ssh_user) {
                        $fail("The {$attribute} field does not match the registered node identity.");
                    }
                },
            ],
            'home_directory' => [
                'required',
                'string',
                static function (string $attribute, mixed $value, Closure $fail): void {
                    if (
                        ! is_string($value)
                        || strlen($value) > 1_024
                        || preg_match('/[\x00-\x1F\x7F]/', $value) === 1
                    ) {
                        $fail("The {$attribute} field is invalid.");
                    }
                },
                function (string $attribute, mixed $value, Closure $fail): void {
                    $node = $this->user();

                    if (! $node instanceof Node || $value !== "/Users/{$node->ssh_user}") {
                        $fail("The {$attribute} field does not match the registered node identity.");
                    }
                },
            ],
        ];
    }

    /** @mago-expect analysis:mixed-assignment Validated setup facts are asserted before data-object construction. */
    public function facts(): MacOsAppDevSetupFactsData
    {
        $platform = $this->validated('platform');
        $architecture = $this->validated('architecture');
        $username = $this->validated('username');
        $homeDirectory = $this->validated('home_directory');
        assert(is_string($platform), description: 'Validated platform must be a string.');
        assert(is_string($architecture), description: 'Validated architecture must be a string.');
        assert(is_string($username), description: 'Validated username must be a string.');
        assert(is_string($homeDirectory), description: 'Validated home directory must be a string.');

        return new MacOsAppDevSetupFactsData(
            platform: $platform,
            architecture: $architecture,
            username: $username,
            homeDirectory: $homeDirectory,
        );
    }
}
