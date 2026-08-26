<?php

declare(strict_types=1);

namespace App\Http\Requests\Nodes;

use App\Domain\Nodes\RoleName;
use App\Infrastructure\Http\TopLevelJsonObjectInspector;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;
use InvalidArgumentException;

final class AddNodeRoleRequest extends FormRequest
{
    protected function prepareForValidation(): void
    {
        try {
            app(TopLevelJsonObjectInspector::class)->inspect($this->getContent(), ['role']);
        } catch (InvalidArgumentException) {
            throw ValidationException::withMessages([
                'body' => ['The request body must be a JSON object with unique allowed keys.'],
            ]);
        }
    }

    /** @return array<string, list<mixed>> */
    public function rules(): array
    {
        return [
            'role' => ['required', 'string', Rule::in([RoleName::AppDev->value])],
        ];
    }

    /** @mago-expect analysis:mixed-assignment The validated role is asserted before enum conversion. */
    public function role(): RoleName
    {
        $role = $this->validated('role');
        assert(is_string($role), description: 'Validated role must be a string.');

        return RoleName::from($role);
    }
}
