<?php

declare(strict_types=1);

namespace App\Infrastructure\Ssh;

use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Processes\ProcessRunner;
use SensitiveParameter;

final readonly class NativeSshExecutor implements SshExecutor
{
    public function __construct(
        private ProcessRunner $runner,
    ) {}

    public function execute(SshConnection $connection, #[SensitiveParameter] RemoteCommand $command): CommandResult
    {
        return $this->runner->run(new ProcessInvocation(
            arguments: [
                'ssh',
                '-i',
                $connection->identityFile,
                '-p',
                (string) $connection->port,
                '-o',
                'BatchMode=yes',
                '-o',
                'StrictHostKeyChecking=yes',
                '-o',
                "UserKnownHostsFile={$connection->knownHostsFile}",
                '-o',
                "ConnectTimeout={$connection->connectTimeout}",
                '--',
                "{$connection->user}@{$connection->host}",
                $command->shellCommand(),
            ],
            timeout: $connection->commandTimeout,
            input: $command->input,
            protectedInput: $command->protectedInput,
        ));
    }
}
