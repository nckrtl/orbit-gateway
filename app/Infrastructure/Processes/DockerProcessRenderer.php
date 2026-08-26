<?php

declare(strict_types=1);

namespace App\Infrastructure\Processes;

use App\Domain\Processes\ProcessTarget;
use App\Models\Process;
use InvalidArgumentException;
use SensitiveParameter;

/**
 * @mago-expect lint:cyclomatic-complexity Docker arguments validate each supported explicit input shape.
 * @mago-expect lint:kan-defect Docker arguments fail closed on malformed persisted configuration.
 */
final readonly class DockerProcessRenderer
{
    public function containerName(#[SensitiveParameter] Process $process): string
    {
        if ($process->id < 1 || preg_match('/\A[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\z/D', $process->name) !== 1) {
            throw new InvalidArgumentException('A process needs a persisted ID and safe name before rendering.');
        }

        return "orbit-process-{$process->id}-{$process->name}";
    }

    /**
     * @return non-empty-list<string>
     *
     * @mago-expect analysis:mixed-assignment Persisted runtime configuration is validated before rendering.
     */
    public function createArguments(
        #[SensitiveParameter]
        Process $process,
        ProcessTarget $target,
        ?string $containerName = null,
    ): array {
        $runtimeConfig = $this->runtimeConfig($process);
        $image = $runtimeConfig['image'] ?? null;
        $command = $this->stringList($runtimeConfig['command'] ?? null);
        $containerName ??= $this->containerName($process);

        if (preg_match('/\A[A-Za-z0-9][A-Za-z0-9_.-]*\z/D', $containerName) !== 1) {
            throw new InvalidArgumentException('A Docker process needs a safe container name.');
        }

        if (
            ! is_string($image)
            || preg_match('/\A[A-Za-z0-9][A-Za-z0-9._\/:@-]*\z/D', $image) !== 1
            || $command === []
        ) {
            throw new InvalidArgumentException('A Docker process needs an image and command argv.');
        }

        $arguments = [
            'sudo',
            'docker',
            'container',
            'create',
            '--name',
            $containerName,
            '--label',
            'orbit.managed=true',
            '--label',
            'orbit.container.kind=process',
            '--label',
            "orbit.process.id={$process->id}",
            '--label',
            'orbit.process.spec='.$this->specHash($process, $target),
            '--restart',
            $this->restartPolicy($process),
            '--workdir',
            $process->working_directory,
        ];

        foreach ($this->stringList($runtimeConfig['ports'] ?? []) as $port) {
            $arguments[] = '--publish';
            $arguments[] = $port;
        }

        foreach ($this->volumes($runtimeConfig['volumes'] ?? []) as $volume) {
            $arguments[] = '--mount';
            $arguments[] = $this->mount($volume);
        }

        return [...$arguments, $image, ...$command];
    }

    public function specHash(#[SensitiveParameter] Process $process, ProcessTarget $target): string
    {
        return hash('sha256', json_encode([
            'runtime_config' => $this->runtimeConfig($process),
            'working_directory' => $process->working_directory,
            'restart_policy' => $process->restart_policy,
            'node_id' => $target->node->id,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
    }

    /** @mago-expect analysis:mixed-assignment Persisted JSON values start at an untyped boundary. */
    public function environmentInput(#[SensitiveParameter] Process $process): ProtectedInput
    {
        $contents = '';
        $environment = array_key_exists('environment', $process->runtime_config)
            ? $process->runtime_config['environment']
            : [];

        foreach ($this->stringMap($environment) as $name => $value) {
            $contents .= "{$name}={$value}\n";
        }

        return ProtectedInput::fromString($contents);
    }

    /** @return array<string, mixed> */
    private function runtimeConfig(#[SensitiveParameter] Process $process): array
    {
        $runtimeConfig = $process->runtime_config;

        if (array_key_exists('environment', $runtimeConfig)) {
            $runtimeConfig['environment'] = $this->stringMap($runtimeConfig['environment']);
        }

        return $runtimeConfig;
    }

    /**
     * @return list<string>
     *
     * @mago-expect analysis:mixed-assignment Persisted JSON values start at an untyped boundary.
     */
    private function stringList(mixed $value): array
    {
        if (! is_array($value)) {
            return [];
        }

        $items = [];

        foreach ($value as $item) {
            if (! is_string($item)) {
                return [];
            }

            $items[] = $item;
        }

        return $items;
    }

    /**
     * @return array<string, string>
     *
     * @mago-expect analysis:mixed-assignment Persisted JSON values start at an untyped boundary.
     */
    private function stringMap(#[SensitiveParameter] mixed $value): array
    {
        if (! is_array($value)) {
            throw new InvalidArgumentException('Docker environment must be a string map.');
        }

        $items = [];

        foreach ($value as $name => $item) {
            if (! is_string($name) || ! is_string($item)) {
                throw new InvalidArgumentException('Docker environment values must be strings.');
            }

            if (
                preg_match('/\A[A-Za-z_][A-Za-z0-9_]*\z/D', $name) !== 1
                || str_contains($item, "\0")
                || str_contains($item, "\r")
                || str_contains($item, "\n")
            ) {
                throw new InvalidArgumentException('Docker environment needs safe names and single-line values.');
            }

            $items[$name] = $item;
        }

        ksort($items);

        return $items;
    }

    /**
     * @return list<array{source: string, target: string, read_only: bool}>
     *
     * @mago-expect analysis:mixed-assignment Persisted JSON values start at an untyped boundary.
     */
    private function volumes(mixed $value): array
    {
        if (! is_array($value)) {
            return [];
        }

        $volumes = [];

        foreach ($value as $volume) {
            if (
                ! is_array($volume)
                || ! is_string($volume['source'] ?? null)
                || ! is_string($volume['target'] ?? null)
            ) {
                throw new InvalidArgumentException('Docker volumes need string source and target values.');
            }

            $volumes[] = [
                'source' => $volume['source'],
                'target' => $volume['target'],
                'read_only' => ($volume['read_only'] ?? false) === true,
            ];
        }

        return $volumes;
    }

    /** @param array{source: string, target: string, read_only: bool} $volume */
    private function mount(array $volume): string
    {
        $type = str_starts_with($volume['source'], '/') ? 'bind' : 'volume';
        $mount = "type={$type},source={$volume['source']},target={$volume['target']}";

        return $volume['read_only'] ? "{$mount},readonly" : $mount;
    }

    private function restartPolicy(#[SensitiveParameter] Process $process): string
    {
        return match ($process->restart_policy) {
            'never' => 'no',
            'on-failure' => 'on-failure',
            'always' => 'always',
            'unless-stopped' => 'unless-stopped',
            default => throw new InvalidArgumentException('Unsupported Docker restart policy.'),
        };
    }
}
