<?php

declare(strict_types=1);

namespace App\Infrastructure\Ssh;

use App\Infrastructure\Processes\CommandResult;
use SensitiveParameter;

interface SshExecutor
{
    public function execute(SshConnection $connection, #[SensitiveParameter] RemoteCommand $command): CommandResult;
}
