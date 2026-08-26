<?php

declare(strict_types=1);

namespace App\Http\Requests\Workspaces;

use App\Data\Workspaces\CreateWorkspaceData;
use App\Domain\AppDev\AppDevHostPaths;
use App\Domain\Shared\ResourceOperationException;
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
                'regex:/\A\/[^\x00-\x1F\x7F]*\z/D',
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

            $instanceId = $this->integer('instance_id');
            $name = $this->string('name')->toString();
            $instance = Instance::query()->with(['app', 'node'])->find($instanceId);

            if ($instance === null || $name === '') {
                return;
            }

            try {
                app(AppDevHostPaths::class)->resolveWorkspaceCheckout(
                    node: $instance->node,
                    app: $instance->app->slug,
                    workspace: $name,
                    override: $this->string('checkout_path')->toString(),
                );
            } catch (ResourceOperationException) {
                if ($instance->node->platform === 'linux') {
                    $validator->errors()->add('checkout_path', 'The checkout path is not a safe Orbit path.');
                }
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
}
