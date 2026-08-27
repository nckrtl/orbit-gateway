<?php

declare(strict_types=1);

namespace App\Http\Requests\Nodes;

use App\Domain\Nodes\RoleName;
use App\Http\Requests\TopLevelJsonObjectInspector;
use Closure;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;
use Illuminate\Validation\Validator;
use UnexpectedValueException;

final class RemoveNodeRoleRequest extends FormRequest
{
    /** @return array<string, list<mixed>> */
    public function rules(): array
    {
        return [
            'role' => ['required', 'string', Rule::enum(RoleName::class)],
            'force' => ['sometimes', $this->strictBoolean(...)],
            'purge_data' => ['sometimes', $this->strictBoolean(...)],
        ];
    }

    /** @return list<callable(Validator): void> */
    public function after(): array
    {
        return [function (Validator $validator): void {
            if ($this->input('purge_data') !== true || $this->input('force') === true) {
                return;
            }

            $validator->errors()->add(
                'force',
                'The force field must be true when purge data is requested.',
            );
        }];
    }

    /** @return array<string, mixed> */
    public function validationData(): array
    {
        try {
            $payload = app(TopLevelJsonObjectInspector::class)->inspect(
                $this->getContent(),
                ['force', 'purge_data'],
            );
        } catch (UnexpectedValueException $exception) {
            throw ValidationException::withMessages(['body' => [$exception->getMessage()]]);
        }
        $role = $this->route('role');

        if (is_string($role)) {
            $payload['role'] = $role;
        }

        return $payload;
    }

    public function role(): RoleName
    {
        return RoleName::from((string) $this->validated('role'));
    }

    public function force(): bool
    {
        return $this->validated('force', false) === true;
    }

    public function purgeData(): bool
    {
        return $this->validated('purge_data', false) === true;
    }

    private function strictBoolean(string $attribute, mixed $value, Closure $fail): void
    {
        if (! is_bool($value)) {
            $fail("The {$attribute} field must be true or false.");
        }
    }
}
