<?php

declare(strict_types=1);

namespace App\Infrastructure\Processes;

use App\Domain\Processes\ProcessTarget;
use App\Models\Process;
use InvalidArgumentException;
use SensitiveParameter;

/**
 * @mago-expect lint:cyclomatic-complexity Launchd rendering validates each persisted command and environment shape.
 * @mago-expect lint:kan-defect Launchd rendering fails closed on unsafe persisted data.
 */
final readonly class LaunchdProcessRenderer
{
    public function label(#[SensitiveParameter] Process $process): string
    {
        if ($process->id < 1 || preg_match('/\A[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\z/D', $process->name) !== 1) {
            throw new InvalidArgumentException('A process needs a persisted ID and safe name before rendering.');
        }

        return "dev.orbit.process.{$process->id}.{$process->name}";
    }

    public function plistPath(#[SensitiveParameter] Process $process, ProcessTarget $target): string
    {
        return "/Users/{$target->user}/Library/LaunchAgents/{$this->label($process)}.plist";
    }

    public function stdoutPath(#[SensitiveParameter] Process $process, ProcessTarget $target): string
    {
        return "/Users/{$target->user}/Library/Logs/Orbit/processes/{$this->label($process)}.stdout.log";
    }

    public function stderrPath(#[SensitiveParameter] Process $process, ProcessTarget $target): string
    {
        return "/Users/{$target->user}/Library/Logs/Orbit/processes/{$this->label($process)}.stderr.log";
    }

    public function render(#[SensitiveParameter] Process $process, ProcessTarget $target): string
    {
        $config = $process->runtime_config;
        $command = $this->stringList($config['command'] ?? null);
        $environment = $this->stringMap($config['environment'] ?? []);

        if ($command === []) {
            throw new InvalidArgumentException('A launchd process needs command argv.');
        }

        $environment = [
            ...$environment,
            'HOME' => "/Users/{$target->user}",
            'PATH' => '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin',
        ];
        ksort($environment);

        $lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
            '<plist version="1.0">',
            '<dict>',
            '  <key>Label</key>',
            '  <string>'.$this->xml($this->label($process)).'</string>',
            '  <key>ProgramArguments</key>',
            '  <array>',
        ];

        foreach ($command as $argument) {
            $lines[] = '    <string>'.$this->xml($argument).'</string>';
        }

        $lines = [
            ...$lines,
            '  </array>',
            '  <key>WorkingDirectory</key>',
            '  <string>'.$this->xml($process->working_directory).'</string>',
            '  <key>EnvironmentVariables</key>',
            '  <dict>',
        ];

        foreach ($environment as $name => $value) {
            $lines[] = '    <key>'.$this->xml($name).'</key>';
            $lines[] = '    <string>'.$this->xml($value).'</string>';
        }

        $lines = [
            ...$lines,
            '  </dict>',
            '  <key>StandardOutPath</key>',
            '  <string>'.$this->xml($this->stdoutPath($process, $target)).'</string>',
            '  <key>StandardErrorPath</key>',
            '  <string>'.$this->xml($this->stderrPath($process, $target)).'</string>',
            '  <key>RunAtLoad</key>',
            '  <false/>',
            ...$this->keepAlive($process->restart_policy),
            '</dict>',
            '</plist>',
            '',
        ];

        return implode("\n", $lines);
    }

    /** @return list<string> */
    private function stringList(mixed $value): array
    {
        if (! is_array($value)) {
            return [];
        }

        $items = [];

        /** @mago-expect analysis:mixed-assignment Persisted JSON values start at an untyped boundary. */
        foreach ($value as $item) {
            if (! is_string($item) || preg_match('//u', $item) !== 1 || preg_match('/[\x00-\x1F\x7F]/', $item) === 1) {
                throw new InvalidArgumentException(
                    'Launchd command arguments must be valid Unicode strings without control bytes.',
                );
            }

            $items[] = $item;
        }

        return $items;
    }

    /** @return array<string, string> */
    private function stringMap(#[SensitiveParameter] mixed $value): array
    {
        if (! is_array($value)) {
            throw new InvalidArgumentException('Launchd environment must be a string map.');
        }

        $items = [];

        /** @mago-expect analysis:mixed-assignment Persisted JSON values start at an untyped boundary. */
        foreach ($value as $name => $item) {
            if (
                ! is_string($name)
                || preg_match('/\A[A-Za-z_][A-Za-z0-9_]*\z/D', $name) !== 1
                || ! is_string($item)
                || ! $this->isXmlSafeValue($item)
            ) {
                throw new InvalidArgumentException('Launchd environment needs safe names and XML-safe string values.');
            }

            $items[$name] = $item;
        }

        return $items;
    }

    private function isXmlSafeValue(string $value): bool
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

    /** @return list<string> */
    private function keepAlive(string $restartPolicy): array
    {
        return match ($restartPolicy) {
            'never' => ['  <key>KeepAlive</key>', '  <false/>'],
            'always', 'unless-stopped' => ['  <key>KeepAlive</key>', '  <true/>'],
            'on-failure' => [
                '  <key>KeepAlive</key>',
                '  <dict>',
                '    <key>SuccessfulExit</key>',
                '    <false/>',
                '  </dict>',
            ],
            default => throw new InvalidArgumentException('Unsupported launchd restart policy.'),
        };
    }

    private function xml(string $value): string
    {
        return htmlspecialchars($value, ENT_XML1 | ENT_QUOTES, encoding: 'UTF-8');
    }
}
