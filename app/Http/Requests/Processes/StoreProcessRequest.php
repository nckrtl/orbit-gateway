<?php

declare(strict_types=1);

namespace App\Http\Requests\Processes;

use App\Data\Processes\AddProcessData;
use App\Domain\Processes\ProcessRuntime;
use App\Domain\Processes\ProcessRuntimeSelector;
use App\Domain\Processes\ProcessTargetResolver;
use App\Domain\Processes\ProcessTargetType;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;
use Illuminate\Validation\Validator;
use SensitiveParameter;

/**
 * @mago-expect lint:cyclomatic-complexity One request validates supported Linux and Darwin runtime shapes.
 * @mago-expect lint:kan-defect Runtime-specific validation stays at the HTTP boundary.
 * @mago-expect lint:too-many-methods The request keeps one raw-input validation boundary for process creation.
 */
final class StoreProcessRequest extends FormRequest
{
    /** @return array<string, list<mixed>> */
    public function rules(): array
    {
        return [
            'target_type' => ['required', Rule::enum(ProcessTargetType::class)],
            'target_id' => ['required', 'integer', 'min:1'],
            'name' => [
                'required',
                'string',
                'max:63',
                'regex:/\A[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\z/D',
            ],
            'runtime' => ['sometimes', 'string'],
            'command' => ['required', 'array', 'min:1', 'max:64'],
            'command.*' => ['string', 'max:4096', 'not_regex:/[\x00\r\n]/'],
            'image' => [
                'sometimes',
                'nullable',
                'string',
                'max:255',
                'regex:/\A[A-Za-z0-9][A-Za-z0-9._\/:@-]*\z/D',
                'not_regex:/[\s\x00-\x1F]/',
            ],
            'working_directory' => [
                'sometimes',
                'string',
                'max:4096',
                'regex:/\A\/(?!.*(?:^|\/)\.\.(?:\/|$))[^\x00\r\n]*\z/D',
            ],
            'environment' => ['sometimes', 'array', 'max:100'],
            'environment.*' => ['string', 'max:4096'],
            'ports' => ['sometimes', 'array', 'max:100'],
            'ports.*' => [
                'string',
                'regex:/\A(?:(?:\d{1,3}\.){3}\d{1,3}:)?\d{1,5}:\d{1,5}(?:\/(?:tcp|udp))?\z/D',
            ],
            'volumes' => ['sometimes', 'array', 'max:100'],
            'volumes.*' => ['array:source,target,read_only'],
            'volumes.*.source' => [
                'required',
                'string',
                'max:4096',
                'regex:/\A(?:\/[A-Za-z0-9._\/ -]+|[A-Za-z0-9][A-Za-z0-9_.-]*)\z/D',
            ],
            'volumes.*.target' => [
                'required',
                'string',
                'max:4096',
                'regex:/\A\/[A-Za-z0-9._\/ -]*\z/D',
            ],
            'volumes.*.read_only' => ['sometimes', 'boolean'],
            'restart_policy' => [
                'sometimes',
                Rule::in(['never', 'on-failure', 'always', 'unless-stopped']),
            ],
            'start' => ['sometimes', 'boolean'],
        ];
    }

    /** @return list<callable(Validator): void> */
    public function after(): array
    {
        return [
            function (#[SensitiveParameter] Validator $validator): void {
                $this->validateRuntimeValue($validator);

                if ($validator->errors()->has('runtime')) {
                    return;
                }

                if (
                    $validator->errors()->has('target_type')
                    || $validator->errors()->has('target_id')
                ) {
                    return;
                }

                $this->validateRuntimeSpecificFields($validator);
                $this->validateSystemdExecutable($validator);
                $this->validateEnvironmentNames($validator);
                $this->validateEnvironmentValues($validator);
                $this->validatePorts($validator);
            },
        ];
    }

    public function payload(): AddProcessData
    {
        /** @var array<string, mixed> $validated */
        $validated = $this->validated();
        /** @var list<string> $command */
        $command = $validated['command'];
        /** @var array<string, string> $environment */
        $environment = is_array($validated['environment'] ?? null) ? $validated['environment'] : [];
        /** @var list<string> $ports */
        $ports = is_array($validated['ports'] ?? null) ? array_values($validated['ports']) : [];
        $volumes = $this->volumes($validated['volumes'] ?? []);

        return new AddProcessData(
            targetType: ProcessTargetType::from((string) $validated['target_type']),
            targetId: (int) $validated['target_id'],
            name: (string) $validated['name'],
            runtime: $this->resolvedRuntime(),
            command: array_values($command),
            image: is_string($validated['image'] ?? null) ? $validated['image'] : null,
            workingDirectory: is_string($validated['working_directory'] ?? null)
                ? $validated['working_directory']
                : null,
            environment: $environment,
            ports: $ports,
            volumes: $volumes,
            restartPolicy: is_string($validated['restart_policy'] ?? null)
                ? $validated['restart_policy']
                : 'never',
            start: ($validated['start'] ?? false) === true,
        );
    }

    /** @mago-expect analysis:mixed-assignment Request input is an untyped boundary. */
    private function validateRuntimeValue(#[SensitiveParameter] Validator $validator): void
    {
        if (! $this->exists('runtime')) {
            return;
        }

        $runtime = $this->runtimeInput();

        if (! is_string($runtime)) {
            $validator->errors()->add('runtime', 'The runtime field must be a string.');

            return;
        }

        if (
            strlen($runtime) > 64
            || preg_match('//u', $runtime) !== 1
            || preg_match('/\p{Cc}/u', $runtime) === 1
        ) {
            $validator->errors()->add('runtime', 'The runtime field format is invalid.');
        }
    }

    private function validateRuntimeSpecificFields(#[SensitiveParameter] Validator $validator): void
    {
        try {
            $runtime = $this->resolvedRuntime();
        } catch (\Throwable) {
            return;
        }

        if (! $runtime instanceof ProcessRuntime) {
            return;
        }

        if (
            $runtime === ProcessRuntime::Docker
            && (! $this->exists('image')
            || ! is_string($this->input('image'))
            || $this->input('image') === '')
        ) {
            $validator->errors()->add('image', 'The image field is required when runtime is docker.');
        }

        if ($runtime === ProcessRuntime::Systemd && $this->exists('environment')) {
            $validator->errors()->add('environment', 'The environment field is prohibited when runtime is systemd.');
        }

        if ($runtime === ProcessRuntime::Docker) {
            return;
        }

        foreach (['image', 'ports', 'volumes'] as $field) {
            if (! $this->exists($field)) {
                continue;
            }

            $validator->errors()->add(
                $field,
                "The {$field} field is prohibited when runtime is {$runtime->value}.",
            );
        }
    }

    /** @mago-expect analysis:mixed-assignment Request input is an untyped boundary. */
    private function validateSystemdExecutable(#[SensitiveParameter] Validator $validator): void
    {
        if ($this->resolvedRuntime()?->value !== ProcessRuntime::Systemd->value) {
            return;
        }

        $executable = $this->input('command.0');

        if (is_string($executable) && str_starts_with($executable, '/')) {
            return;
        }

        $validator->errors()->add('command.0', 'The systemd executable must be an absolute path.');
    }

    /** @mago-expect analysis:mixed-assignment Request input is an untyped boundary. */
    private function validateEnvironmentNames(#[SensitiveParameter] Validator $validator): void
    {
        $environment = $this->input('environment');

        if (! is_array($environment)) {
            return;
        }

        foreach (array_keys($environment) as $name) {
            if (is_string($name) && preg_match('/\A[A-Za-z_][A-Za-z0-9_]*\z/D', $name) === 1) {
                continue;
            }

            foreach ($validator->errors()->keys() as $field) {
                if (! str_starts_with($field, 'environment.')) {
                    continue;
                }

                $validator->errors()->forget($field);
            }

            $validator->errors()->add('environment', 'The environment contains an invalid variable name.');

            return;
        }
    }

    /** @mago-expect analysis:mixed-assignment Request input is an untyped boundary. */
    private function validateEnvironmentValues(#[SensitiveParameter] Validator $validator): void
    {
        $environment = $this->input('environment');

        if (! is_array($environment)) {
            return;
        }

        foreach ($environment as $name => $value) {
            if (! is_string($name) || preg_match('/\A[A-Za-z_][A-Za-z0-9_]*\z/D', $name) !== 1) {
                return;
            }

            if (! is_string($value) || ! $this->isXmlSafeEnvironmentValue($value)) {
                $validator->errors()->add("environment.{$name}", 'The environment contains an invalid value.');

                return;
            }
        }
    }

    private function isXmlSafeEnvironmentValue(string $value): bool
    {
        return (
            preg_match('//u', $value) === 1
            && preg_match('/\p{Cc}/u', $value) !== 1
            && preg_match(
                '/\A(?:[\x{20}-\x{D7FF}]|[\x{E000}-\x{FFFD}]|[\x{10000}-\x{10FFFF}])*\z/uD',
                $value,
            ) === 1
        );
    }

    /** @mago-expect analysis:mixed-assignment Request input is an untyped boundary. */
    private function validatePorts(#[SensitiveParameter] Validator $validator): void
    {
        $ports = $this->input('ports');

        if (! is_array($ports)) {
            return;
        }

        foreach ($ports as $index => $port) {
            if (! is_string($port)) {
                continue;
            }

            $withoutProtocol = explode('/', $port, limit: 2)[0];
            $segments = explode(':', $withoutProtocol);
            $numericPorts = array_slice($segments, -2);
            $valid = count($numericPorts) === 2;

            foreach ($numericPorts as $numericPort) {
                $number = filter_var($numericPort, FILTER_VALIDATE_INT);
                $valid = $valid && is_int($number) && $number >= 1 && $number <= 65_535;
            }

            if ($valid) {
                continue;
            }

            $validator->errors()->add("ports.{$index}", 'Published ports must be between 1 and 65535.');
        }
    }

    /** @mago-expect analysis:mixed-assignment Request input remains mixed until the runtime boundary checks it. */
    private function resolvedRuntime(): ?ProcessRuntime
    {
        $runtime = $this->runtimeInput();

        if (! $this->exists('runtime')) {
            return app(ProcessRuntimeSelector::class)->select(null, $this->target()->node->platform);
        }

        if (! is_string($runtime)) {
            return null;
        }

        if ($runtime === '') {
            throw ValidationException::withMessages([
                'runtime' => ['The selected runtime is invalid.'],
            ]);
        }

        $selected = ProcessRuntime::tryFrom($runtime);

        if ($selected === null) {
            throw ValidationException::withMessages([
                'runtime' => ['The selected runtime is invalid.'],
            ]);
        }

        return app(ProcessRuntimeSelector::class)->select($selected, $this->target()->node->platform);
    }

    /** @mago-expect analysis:mixed-assignment Decoded JSON remains mixed until the caller validates it. */
    private function runtimeInput(): mixed
    {
        $content = $this->getContent();

        if ($content === '') {
            return $this->input('runtime');
        }

        try {
            $payload = json_decode($content, associative: true, flags: JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            return $this->input('runtime');
        }

        if (! is_array($payload) || ! array_key_exists('runtime', $payload)) {
            return $this->input('runtime');
        }

        return $payload['runtime'];
    }

    private function target(): \App\Domain\Processes\ProcessTarget
    {
        return app(ProcessTargetResolver::class)->resolve(
            ProcessTargetType::from((string) $this->input('target_type')),
            (int) $this->input('target_id'),
        );
    }

    /**
     * @return list<array{source: string, target: string, read_only: bool}>
     *
     * @mago-expect analysis:mixed-assignment Validated request arrays start at an untyped boundary.
     */
    private function volumes(mixed $value): array
    {
        if (! is_array($value)) {
            return [];
        }

        $volumes = [];

        foreach ($value as $volume) {
            if (! is_array($volume)) {
                continue;
            }

            $volumes[] = [
                'source' => (string) $volume['source'],
                'target' => (string) $volume['target'],
                'read_only' => ($volume['read_only'] ?? false) === true,
            ];
        }

        return $volumes;
    }
}
