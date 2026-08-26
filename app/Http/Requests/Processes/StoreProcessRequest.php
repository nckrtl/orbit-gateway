<?php

declare(strict_types=1);

namespace App\Http\Requests\Processes;

use App\Data\Processes\AddProcessData;
use App\Domain\Processes\ProcessRuntime;
use App\Domain\Processes\ProcessTargetType;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Validator;
use SensitiveParameter;

/**
 * @mago-expect lint:cyclomatic-complexity One request validates both explicit supported runtime shapes.
 * @mago-expect lint:kan-defect Runtime-specific validation stays at the HTTP boundary.
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
            'runtime' => ['required', Rule::enum(ProcessRuntime::class)],
            'command' => ['required', 'array', 'min:1', 'max:64'],
            'command.*' => ['string', 'max:4096', 'not_regex:/[\x00\r\n]/'],
            'image' => [
                'required_if:runtime,docker',
                'prohibited_unless:runtime,docker',
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
            'environment' => ['sometimes', 'prohibited_unless:runtime,docker', 'array', 'max:100'],
            'environment.*' => ['string', 'max:4096', 'not_regex:/[\x00\r\n]/'],
            'ports' => ['sometimes', 'prohibited_unless:runtime,docker', 'array', 'max:100'],
            'ports.*' => [
                'string',
                'regex:/\A(?:(?:\d{1,3}\.){3}\d{1,3}:)?\d{1,5}:\d{1,5}(?:\/(?:tcp|udp))?\z/D',
            ],
            'volumes' => ['sometimes', 'prohibited_unless:runtime,docker', 'array', 'max:100'],
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
                $this->validateSystemdExecutable($validator);
                $this->validateEnvironmentNames($validator);
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
            runtime: ProcessRuntime::from((string) $validated['runtime']),
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
    private function validateSystemdExecutable(#[SensitiveParameter] Validator $validator): void
    {
        if ($this->input('runtime') !== ProcessRuntime::Systemd->value) {
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

            $validator->errors()->add(
                'environment',
                'The environment contains an invalid variable name.',
            );

            return;
        }
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
