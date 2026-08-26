<?php

declare(strict_types=1);

namespace App\Console\Commands;

use App\Actions\Gateway\ConvergeGatewayWebAction;
use Illuminate\Console\Command;

final class ConvergeGatewayWebCommand extends Command
{
    #[\Override]
    protected $signature = 'orbit:gateway-web:converge';

    #[\Override]
    protected $description = 'Republish the Gateway-local web configuration from stored state';

    public function handle(ConvergeGatewayWebAction $action): int
    {
        $action->execute();
        $this->info('Gateway web configuration converged.');

        return self::SUCCESS;
    }
}
