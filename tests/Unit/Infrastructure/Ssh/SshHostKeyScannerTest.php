<?php

declare(strict_types=1);

use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Processes\ProcessRunner;
use App\Infrastructure\Ssh\SshHostKeyScanException;
use App\Infrastructure\Ssh\SshHostKeyScanner;

it('scans and fingerprints the preferred SSH host key', function (): void {
    $runner = new class implements ProcessRunner {
        /** @var list<ProcessInvocation> */
        public array $invocations = [];

        public function run(ProcessInvocation $invocation): CommandResult
        {
            $this->invocations[] = $invocation;

            if (count($this->invocations) === 1) {
                return new CommandResult(
                    0,
                    "[94.237.40.75]:2222 ssh-rsa RSAKEY\n[94.237.40.75]:2222 ssh-ed25519 EDKEY\n",
                    '',
                    5,
                    false,
                );
            }

            return new CommandResult(0, '256 SHA256:abc root@node (ED25519)', '', 2, false);
        }
    };
    $scanner = new SshHostKeyScanner($runner);

    $key = $scanner->scan('94.237.40.75', 2222);

    expect($key->type)
        ->toBe('ssh-ed25519')
        ->and($key->value)
        ->toBe('EDKEY')
        ->and($key->fingerprint)
        ->toBe('SHA256:abc')
        ->and($runner->invocations[0]->arguments)
        ->toBe([
            'ssh-keyscan',
            '-T',
            '10',
            '-p',
            '2222',
            '--',
            '94.237.40.75',
        ])
        ->and($runner->invocations[1]->input)
        ->toBe("[94.237.40.75]:2222 ssh-ed25519 EDKEY\n");
});

it('keeps bounded command diagnostics when the host key scan fails', function (): void {
    $result = new CommandResult(
        255,
        '',
        'ssh-keyscan failed',
        15_000,
        true,
    );
    $runner = new class($result) implements ProcessRunner {
        /** @var list<ProcessInvocation> */
        public array $invocations = [];

        public function __construct(
            private readonly CommandResult $result,
        ) {}

        public function run(ProcessInvocation $invocation): CommandResult
        {
            $this->invocations[] = $invocation;

            return $this->result;
        }
    };
    $scanner = new SshHostKeyScanner($runner);
    $exception = null;

    try {
        $scanner->scan('192.0.2.63', 22);
    } catch (SshHostKeyScanException $caught) {
        $exception = $caught;
    }

    expect($exception)
        ->toBeInstanceOf(SshHostKeyScanException::class)
        ->and($exception?->result)
        ->toBe($result)
        ->and($runner->invocations)
        ->toHaveCount(1);
});
