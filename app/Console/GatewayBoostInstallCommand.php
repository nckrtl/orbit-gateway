<?php

declare(strict_types=1);

namespace App\Console;

use Laravel\Boost\Console\InstallCommand;
use Laravel\Boost\Install\GuidelineComposer;

final class GatewayBoostInstallCommand extends InstallCommand
{
    protected function syncRuleFiles(GuidelineComposer $composer): void
    {
        $composer->resolvedGuidelines();

        parent::syncRuleFiles($composer);
    }
}
