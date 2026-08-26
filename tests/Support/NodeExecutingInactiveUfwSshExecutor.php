<?php

declare(strict_types=1);

namespace Tests\Support;

use App\Infrastructure\Firewall\UfwStoredRuleProbe;
use App\Infrastructure\Processes\CommandResult;
use App\Infrastructure\Processes\NativeProcessRunner;
use App\Infrastructure\Processes\ProcessInvocation;
use App\Infrastructure\Ssh\RemoteCommand;
use App\Infrastructure\Ssh\SshConnection;
use App\Infrastructure\Ssh\SshExecutor;

final class NodeExecutingInactiveUfwSshExecutor implements SshExecutor
{
    /** @var list<array{connection: SshConnection, command: RemoteCommand}> */
    public array $calls = [];

    public string $storedOutput = '';

    public function __construct(
        private readonly string $ipv4Path,
        private readonly string $ipv6Path,
    ) {}

    public function execute(SshConnection $connection, RemoteCommand $command): CommandResult
    {
        $this->calls[] = ['connection' => $connection, 'command' => $command];

        if ($command->arguments === ['sudo', 'ufw', 'status', 'numbered']) {
            return new CommandResult(
                exitCode: 0,
                stdout: "Status: inactive\n",
                stderr: '',
                durationMs: 10,
                truncated: false,
            );
        }

        if ($command->arguments === UfwStoredRuleProbe::arguments()) {
            return $this->executeStoredRuleProbe($command);
        }

        return new CommandResult(
            exitCode: 0,
            stdout: '',
            stderr: '',
            durationMs: 10,
            truncated: false,
        );
    }

    private function executeStoredRuleProbe(RemoteCommand $command): CommandResult
    {
        $script = $command->arguments[2];
        $script = str_replace('/etc/ufw/user6.rules', $this->ipv6Path, $script);
        $result = new NativeProcessRunner()->run(new ProcessInvocation(
            ['awk', $script, $this->ipv4Path, $this->ipv6Path],
            timeout: 10,
        ));
        $this->storedOutput = $result->stdout;

        return $result;
    }
}
