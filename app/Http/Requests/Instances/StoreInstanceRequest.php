<?php

declare(strict_types=1);

namespace App\Http\Requests\Instances;

use App\Data\Instances\CreateInstanceData;
use App\Models\App as OrbitApp;
use App\Models\Node;
use App\Rules\SupportedPhpVersion;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

final class StoreInstanceRequest extends FormRequest
{
    /** @return array<string, list<mixed>> */
    public function rules(): array
    {
        return [
            'app_id' => ['required', 'integer', Rule::exists(new OrbitApp()->getTable(), 'id')],
            'node_id' => ['required', 'integer', Rule::exists(new Node()->getTable(), 'id')],
            'name' => [
                'required',
                'string',
                'max:63',
                'regex:/\A[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\z/',
            ],
            'environment' => ['sometimes', 'string', 'alpha_dash:ascii', 'max:63'],
            'document_root' => [
                'sometimes',
                'string',
                'max:255',
                'regex:/\A(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._\/-]+\z/',
            ],
            'php_version' => ['sometimes', 'string', new SupportedPhpVersion],
        ];
    }

    public function payload(): CreateInstanceData
    {
        /** @var array<string, mixed> $validated */
        $validated = $this->validated();

        return new CreateInstanceData(
            appId: (int) $validated['app_id'],
            nodeId: (int) $validated['node_id'],
            name: (string) $validated['name'],
            environment: is_string($validated['environment'] ?? null)
                ? $validated['environment']
                : 'development',
            documentRoot: is_string($validated['document_root'] ?? null)
                ? $validated['document_root']
                : 'public',
            phpVersion: is_string($validated['php_version'] ?? null) ? $validated['php_version'] : '8.5',
        );
    }
}
