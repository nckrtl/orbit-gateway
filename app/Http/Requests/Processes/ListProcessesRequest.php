<?php

declare(strict_types=1);

namespace App\Http\Requests\Processes;

use App\Domain\Processes\ProcessTargetType;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

final class ListProcessesRequest extends FormRequest
{
    /** @return array<string, list<mixed>> */
    public function rules(): array
    {
        return [
            'target_type' => ['required', Rule::enum(ProcessTargetType::class)],
            'target_id' => ['required', 'integer', 'min:1'],
        ];
    }

    public function targetType(): ProcessTargetType
    {
        return ProcessTargetType::from((string) $this->validated('target_type'));
    }

    public function targetId(): int
    {
        return (int) $this->validated('target_id');
    }
}
