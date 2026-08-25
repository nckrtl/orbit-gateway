<?php

declare(strict_types=1);

namespace App\Http\Requests\Workspaces;

use App\Rules\SupportedPhpVersion;
use Illuminate\Foundation\Http\FormRequest;

final class UpdateWorkspacePhpRequest extends FormRequest
{
    /** @return array<string, list<mixed>> */
    public function rules(): array
    {
        return [
            'php_version' => [
                'required',
                'string',
                new SupportedPhpVersion,
            ],
        ];
    }

    public function phpVersion(): string
    {
        return $this->string('php_version')->toString();
    }
}
