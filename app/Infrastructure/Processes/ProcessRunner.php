<?php

declare(strict_types=1);

namespace App\Infrastructure\Processes;

use SensitiveParameter;

interface ProcessRunner
{
    public function run(#[SensitiveParameter] ProcessInvocation $invocation): CommandResult;
}
