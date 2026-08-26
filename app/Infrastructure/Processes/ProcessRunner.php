<?php

declare(strict_types=1);

namespace App\Infrastructure\Processes;

interface ProcessRunner
{
    public function run(ProcessInvocation $invocation): CommandResult;
}
