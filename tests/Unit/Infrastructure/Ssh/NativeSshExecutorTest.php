<?php

declare(strict_types=1);

use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Processes\ProcessRunner;
use App\Infrastructure\Ssh\NativeSshExecutor;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshConnection;

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
