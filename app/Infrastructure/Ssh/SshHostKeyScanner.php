<?php

declare(strict_types=1);

namespace App\Infrastructure\Ssh;

use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Processes\ProcessRunner;

final readonly class SshHostKeyScanner implements HostKeyScanner
{
    public function __construct(
        private ProcessRunner $runner,
    ) {}

    public function scan(string $host, int $port): HostKey
    {
        $scan = $this->runner->run(new ProcessInvocation(
            arguments: [
                'ssh-keyscan',
                '-T',
                '10',
                '-p',
                (string) $port,
                '--',
                $host,
            ],
            timeout: 15.0,
        ));

        if (! $scan->succeeded()) {
            throw new SshHostKeyScanException(
                message: "Could not scan the SSH host key for [{$host}:{$port}].",
                result: $scan,
            );
        }

        $line = $this->preferredKeyLine($scan->stdout);
        [$hostLabel, $type, $value] = array_pad(
            array: explode(separator: ' ', string: $line, limit: 3),
            length: 3,
            value: '',
        );

        if ($hostLabel === '' || $type === '' || $value === '') {
            throw new SshHostKeyScanException("SSH host [{$host}:{$port}] returned an invalid host key.");
        }

        $fingerprint = $this->runner->run(new ProcessInvocation(
            arguments: ['ssh-keygen', '-lf', '-', '-E', 'sha256'],
            timeout: 10.0,
            input: $line.PHP_EOL,
        ));

        $matches = [];

        if (! $fingerprint->succeeded() || preg_match('/\b(SHA256:[^\s]+)/', $fingerprint->stdout, $matches) !== 1) {
            throw new SshHostKeyScanException(
                message: "Could not fingerprint the SSH host key for [{$host}:{$port}].",
                result: $fingerprint,
            );
        }

        return new HostKey(
            type: $type,
            value: $value,
            fingerprint: $matches[1],
        );
    }

    private function preferredKeyLine(string $output): string
    {
        $splitLines = preg_split('/\R/', trim($output));
        $lines = is_array($splitLines) ? $splitLines : [];

        foreach (['ssh-ed25519', 'ecdsa-sha2-nistp256', 'ssh-rsa'] as $type) {
            foreach ($lines as $line) {
                if (str_contains($line, " {$type} ")) {
                    return $line;
                }
            }
        }

        throw new SshHostKeyScanException('The SSH host did not return a supported host key.');
    }
}
