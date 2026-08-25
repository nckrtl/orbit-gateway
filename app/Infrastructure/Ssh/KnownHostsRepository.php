<?php

declare(strict_types=1);

namespace App\Infrastructure\Ssh;

use InvalidArgumentException;
use RuntimeException;

final readonly class KnownHostsRepository implements KnownHostsStore
{
    public function __construct(
        private string $path,
    ) {}

    public function path(): string
    {
        return $this->path;
    }

    public function put(string $host, int $port, HostKey $key): void
    {
        if ($host === '' || preg_match('/\s/', $host) === 1) {
            throw new InvalidArgumentException('SSH host names cannot contain whitespace.');
        }

        $directory = dirname($this->path);

        if (
            ! is_dir($directory)
            && ! mkdir(directory: $directory, permissions: 0o700, recursive: true)
            && ! is_dir($directory)
        ) {
            throw new RuntimeException("Could not create SSH directory [{$directory}].");
        }

        chmod(filename: $directory, permissions: 0o700);

        $hostLabel = $port === 22 ? $host : "[{$host}]:{$port}";
        $lines = $this->lines();
        $lines = array_values(array_filter(
            $lines,
            static fn (string $line): bool => ! str_starts_with($line, $hostLabel.' '),
        ));
        $lines[] = "{$hostLabel} {$key->type} {$key->value}";

        $temporaryPath = $this->path.'.tmp';
        $contents = implode(PHP_EOL, $lines).PHP_EOL;

        if (file_put_contents($temporaryPath, $contents, LOCK_EX) === false) {
            throw new RuntimeException("Could not write SSH host keys [{$temporaryPath}].");
        }

        chmod(filename: $temporaryPath, permissions: 0o600);

        if (! rename($temporaryPath, $this->path)) {
            throw new RuntimeException("Could not install SSH host keys [{$this->path}].");
        }
    }

    /** @return list<string> */
    private function lines(): array
    {
        if (! is_file($this->path)) {
            return [];
        }

        $contents = file_get_contents($this->path);

        if (! is_string($contents)) {
            throw new RuntimeException("Could not read SSH host keys [{$this->path}].");
        }

        $splitLines = preg_split('/\R/', trim($contents));
        $lines = is_array($splitLines) ? $splitLines : [];

        return array_values(array_filter($lines, static fn (string $line): bool => $line !== ''));
    }
}
