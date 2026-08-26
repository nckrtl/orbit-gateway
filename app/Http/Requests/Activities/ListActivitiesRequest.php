<?php

declare(strict_types=1);

namespace App\Http\Requests\Activities;

use Illuminate\Foundation\Http\FormRequest;

final class ListActivitiesRequest extends FormRequest
{
    /** @return array<string, list<mixed>> */
    public function rules(): array
    {
        return [
            'limit' => ['sometimes', 'integer', 'min:1', 'max:200'],
            'request_id' => ['sometimes', 'uuid'],
        ];
    }

    public function limit(): int
    {
        return (int) ($this->validated('limit') ?? 25);
    }

    /** @mago-expect analysis:mixed-assignment Validated request values are untyped until inspected below. */
    public function requestId(): ?string
    {
        $requestId = $this->validated('request_id');

        return is_string($requestId) ? $requestId : null;
    }
}
