<?php

declare(strict_types=1);

namespace App\Http\Requests\Processes;

use Illuminate\Foundation\Http\FormRequest;

final class ProcessLogsRequest extends FormRequest
{
    /** @return array<string, list<mixed>> */
    public function rules(): array
    {
        return [
            'lines' => ['sometimes', 'integer', 'min:1', 'max:1000'],
            'follow' => ['prohibited'],
        ];
    }

    public function lines(): int
    {
        return (int) ($this->validated('lines') ?? 100);
    }
}
