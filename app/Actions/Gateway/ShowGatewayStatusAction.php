<?php

declare(strict_types=1);

namespace App\Actions\Gateway;

use App\Data\Gateway\GatewayStatusData;
use Illuminate\Foundation\Application;

final readonly class ShowGatewayStatusAction
{
    public function handle(): GatewayStatusData
    {
        return new GatewayStatusData(
            name: 'orbit-gateway',
            status: 'ok',
            version: (string) config('app.version'),
            phpVersion: PHP_VERSION,
            laravelVersion: Application::VERSION,
        );
    }
}
