<?php

declare(strict_types=1);

namespace App\Http\Requests\Workspaces;

use App\Data\Workspaces\CreateWorkspaceData;
use App\Models\Instance;
use App\Rules\SupportedPhpVersion;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Validator;

final class StoreWorkspaceRequest extends FormRequest
{
    /** @return array<string, list<mixed>> */
    public function rules(): array
    {
        return [
            'instance_id' => ['required', 'integer', Rule::exists(new Instance()->getTable(), 'id')],
            'name' => [
                'required',
                'string',
                'max:63',
                'regex:/\A[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\z/',
            ],
            'branch' => ['sometimes', 'string', 'max:255', 'regex:/\A[A-Za-z0-9][A-Za-z0-9._\/-]*\z/'],
            'checkout_path' => [
                'nullable',
                'string',
                'max:1024',
                'regex:/\A\/home\/orbit\/.+\z/',
            ],
            'php_version' => [
                'nullable',
                'string',
                new SupportedPhpVersion,
            ],
        ];
    }

    /** @return list<callable(Validator): void> */
    public function after(): array
    {
        return [function (Validator $validator): void {
            if (! $this->filled('checkout_path')) {
                return;
            }

            $path = $this->string('checkout_path')->toString();

            if (! $this->checkoutPathIsSafe($path)) {
                $validator->errors()->add('checkout_path', 'The checkout path is not a safe Orbit path.');
            }
        }];
    }

    public function payload(): CreateWorkspaceData
    {
        /** @var array<string, mixed> $validated */
        $validated = $this->validated();
        $name = (string) $validated['name'];

        return new CreateWorkspaceData(
            instanceId: (int) $validated['instance_id'],
            name: $name,
            branch: is_string($validated['branch'] ?? null) ? $validated['branch'] : $name,
            checkoutPath: is_string($validated['checkout_path'] ?? null) ? $validated['checkout_path'] : null,
            phpVersion: is_string($validated['php_version'] ?? null) ? $validated['php_version'] : null,
        );
    }

    private function checkoutPathIsSafe(string $path): bool
    {
        if (! str_starts_with($path, '/home/orbit/')) {
            return false;
        }

        $segments = explode('/', mb_substr($path, mb_strlen('/home/orbit/')));

        if (preg_match('#\A/home/orbit/(?:apps(?:/|\z)|\.(?!orbit/worktrees/))#', $path) === 1) {
            return false;
        }

        foreach ($segments as $segment) {
            if ($segment === '' || $segment === '.' || $segment === '..') {
                return false;
            }

            if (preg_match('/\A[A-Za-z0-9._-]+\z/', $segment) !== 1) {
                return false;
            }
        }

        return true;
    }
}
