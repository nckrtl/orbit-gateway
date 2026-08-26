<?php

declare(strict_types=1);

namespace App\Infrastructure\Processes;

use SensitiveParameter;
use Symfony\Component\Process\Process as SymfonyProcess;

final readonly class NativeProcessRunner implements ProcessRunner
{
    public function __construct(
        private int $maxOutputBytes = 65_536,
        private ?CommandDeadline $deadline = null,
    ) {}

    public function run(#[SensitiveParameter] ProcessInvocation $invocation): CommandResult
    {
        $protectedInput = $invocation->protectedInput;

        try {
            $process = new SymfonyProcess($invocation->arguments);
            $process->setTimeout($this->deadline?->cap($invocation->timeout) ?? $invocation->timeout);
            $process->setInput($protectedInput?->stream() ?? $invocation->input);

            $stdout = '';
            $stderr = '';
            $truncated = false;
            $startedAt = microtime(true);

            $exitCode = $process->run(function (string $type, string $buffer) use (
                &$stdout,
                &$stderr,
                &$truncated,
            ): void {
                if ($type === SymfonyProcess::OUT) {
                    $stdout = $this->appendBounded($stdout, $buffer, $truncated);

                    return;
                }

                $stderr = $this->appendBounded($stderr, $buffer, $truncated);
            });

            return new CommandResult(
                exitCode: $exitCode,
                stdout: $stdout,
                stderr: $stderr,
                durationMs: (int) round((microtime(true) - $startedAt) * 1_000),
                truncated: $truncated,
            );
        } finally {
            $protectedInput?->close();
        }
    }

    private function appendBounded(string $current, string $buffer, bool &$truncated): string
    {
        $combined = $current.$buffer;

        if (strlen($combined) <= $this->maxOutputBytes) {
            return $combined;
        }

        $truncated = true;

        return substr($combined, -$this->maxOutputBytes);
    }
}
