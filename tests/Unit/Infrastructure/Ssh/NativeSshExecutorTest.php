<?php

declare(strict_types=1);

use App\Infrastructure\MacOs\MacOsSteadyStateCommandGuard;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Processes\NativeProcessRunner;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Processes\ProcessRunner;
use App\Infrastructure\Processes\ProtectedInput;
use App\Infrastructure\Ssh\NativeSshExecutor;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshConnection;
use App\Infrastructure\Ssh\SshExecutor;

it('builds strict argument-safe SSH invocations', function (): void {
    $runner = new class implements ProcessRunner {
        public ?ProcessInvocation $invocation = null;

        public function run(ProcessInvocation $invocation): CommandResult
        {
            $this->invocation = $invocation;

            return new CommandResult(0, 'ok', '', 12, false);
        }
    };
    $executor = new NativeSshExecutor($runner);
    $connection = new SshConnection(
        host: '10.44.0.3',
        user: 'orbit',
        port: 22,
        identityFile: '/home/orbit/.orbit/ssh/id_ed25519',
        knownHostsFile: '/home/orbit/.orbit/ssh/known_hosts',
    );

    $result = $executor->execute(
        $connection,
        new RemoteCommand(['systemctl', 'restart', 'orbit-app; touch /tmp/unsafe']),
    );

    expect($result->succeeded())
        ->toBeTrue()
        ->and($runner->invocation?->arguments)
        ->toBe([
            'ssh',
            '-i',
            '/home/orbit/.orbit/ssh/id_ed25519',
            '-p',
            '22',
            '-o',
            'BatchMode=yes',
            '-o',
            'StrictHostKeyChecking=yes',
            '-o',
            'UserKnownHostsFile=/home/orbit/.orbit/ssh/known_hosts',
            '-o',
            'ConnectTimeout=10',
            '--',
            'orbit@10.44.0.3',
            "'systemctl' 'restart' 'orbit-app; touch /tmp/unsafe'",
        ])
        ->and($runner->invocation?->timeout)
        ->toBe(900.0);
});

it('passes protected stdin without adding its bytes to the local SSH invocation', function (): void {
    $sensitiveValue = 'ALPHA=opaque-value';
    $input = ProtectedInput::fromString($sensitiveValue);
    $runner = new class implements ProcessRunner {
        public ?ProcessInvocation $invocation = null;

        public ?string $inputHash = null;

        public function run(ProcessInvocation $invocation): CommandResult
        {
            $this->invocation = $invocation;

            if ($invocation->protectedInput instanceof ProtectedInput) {
                $this->inputHash = hash('sha256', stream_get_contents($invocation->protectedInput->stream()));
                $invocation->protectedInput->close();
            }

            return new CommandResult(0, 'ok', '', 1, false);
        }
    };
    $connection = new SshConnection(
        host: '10.44.0.3',
        user: 'orbit',
        port: 22,
        identityFile: '/home/orbit/.orbit/ssh/id_ed25519',
        knownHostsFile: '/home/orbit/.orbit/ssh/known_hosts',
    );

    new NativeSshExecutor($runner)->execute(
        $connection,
        new RemoteCommand(['cat'], protectedInput: $input),
    );

    $debugOutput = print_r($runner->invocation, return: true);

    expect($runner->invocation?->input)
        ->toBeNull()
        ->and($runner->invocation?->protectedInput)
        ->toBeInstanceOf(ProtectedInput::class)
        ->and(implode("\0", $runner->invocation->arguments ?? []))
        ->not->toContain($sensitiveValue)->and($runner->inputHash)->toBe(hash('sha256', $sensitiveValue))->and(
            $debugOutput,
        )
        ->not->toContain($sensitiveValue)->toContain('[PROTECTED]');
});

it('marks every production protected-input transport parameter sensitive', function (
    string $class,
    string $method,
    string $parameter,
): void {
    $parameters = new ReflectionMethod($class, $method)->getParameters();
    $sensitive = array_find(
        $parameters,
        static fn (ReflectionParameter $candidate): bool => $candidate->name === $parameter,
    );

    expect($sensitive)
        ->toBeInstanceOf(ReflectionParameter::class)
        ->and($sensitive->getAttributes(SensitiveParameter::class))
        ->toHaveCount(1);
})->with([
    'steady-state guard command' => [MacOsSteadyStateCommandGuard::class, 'guard', 'command'],
    'SSH interface command' => [SshExecutor::class, 'execute', 'command'],
    'native SSH command' => [NativeSshExecutor::class, 'execute', 'command'],
    'runner interface invocation' => [ProcessRunner::class, 'run', 'invocation'],
    'native runner invocation' => [NativeProcessRunner::class, 'run', 'invocation'],
    'invocation protected input' => [ProcessInvocation::class, '__construct', 'protectedInput'],
    'remote command protected input' => [RemoteCommand::class, '__construct', 'protectedInput'],
]);

it('keeps protected stdin bytes out of the production transport exception trace', function (): void {
    $sentinel = 'protected-transport-trace-sentinel';
    $runner = new class implements ProcessRunner {
        public function run(ProcessInvocation $invocation): CommandResult
        {
            throw new RuntimeException('The test transport failed.');
        }
    };
    $connection = new SshConnection(
        host: '10.44.0.3',
        user: 'orbit',
        port: 22,
        identityFile: '/home/orbit/.orbit/ssh/id_ed25519',
        knownHostsFile: '/home/orbit/.orbit/ssh/known_hosts',
    );

    try {
        new NativeSshExecutor($runner)->execute(
            $connection,
            new RemoteCommand(['cat'], protectedInput: ProtectedInput::fromString($sentinel)),
        );
    } catch (RuntimeException $exception) {
        $productionTrace = array_values(array_filter(
            $exception->getTrace(),
            static fn (array $frame): bool => (
                is_string($frame['file'] ?? null)
                && str_starts_with($frame['file'], dirname(__DIR__, levels: 4).'/app/')
            ),
        ));

        expect(json_encode($productionTrace, JSON_THROW_ON_ERROR))->not->toContain($sentinel);

        return;
    }

    $this->fail('Expected the protected transport to fail.');
});
