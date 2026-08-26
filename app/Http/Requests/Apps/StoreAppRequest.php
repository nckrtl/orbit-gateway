<?php

declare(strict_types=1);

namespace App\Http\Requests\Apps;

use App\Data\Apps\CreateAppData;
use App\Domain\SourceControl\GitRepositoryOrigin;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Validator;

final class StoreAppRequest extends FormRequest
{
    /** @return array<string, list<mixed>> */
    public function rules(): array
    {
        return [
            'name' => ['sometimes', 'string', 'max:255'],
            'slug' => ['required', 'string', 'alpha_dash:ascii', 'max:63'],
            'repository_url' => ['required', 'string', 'max:2048'],
            'defaults' => ['nullable', 'array'],
        ];
    }

    /** @return list<callable(Validator): void> */
    public function after(): array
    {
        return [function (Validator $validator): void {
            if (! is_string($this->input('repository_url'))) {
                return;
            }

            $repository = $this->string('repository_url')->toString();

            if ($repository === '' || GitRepositoryOrigin::isValid($repository)) {
                return;
            }

            $validator->errors()->add(
                'repository_url',
                'The repository URL must be a valid HTTPS or SSH Git origin.',
            );
        }];
    }

    public function payload(): CreateAppData
    {
        /** @var array<string, mixed> $validated */
        $validated = $this->validated();
        $slug = (string) $validated['slug'];
        $defaults = is_array($validated['defaults'] ?? null) ? $validated['defaults'] : null;

        return new CreateAppData(
            name: is_string($validated['name'] ?? null) ? $validated['name'] : $slug,
            slug: $slug,
            repositoryUrl: (string) $validated['repository_url'],
            defaults: $defaults,
        );
    }
}
