<?php

declare(strict_types=1);

namespace App\Infrastructure\Ssh;

use App\Infrastructure\Processes\CommandResult;

interface SshExecutor
{
    public function execute(SshConnection $connection, RemoteCommand $command): CommandResult;
}
