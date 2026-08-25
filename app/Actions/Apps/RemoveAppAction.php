<?php

declare(strict_types=1);

namespace App\Actions\Apps;

use App\Domain\Shared\ResourceOperationException;
use App\Models\App as OrbitApp;

final readonly class RemoveAppAction
{
    public function execute(OrbitApp $app): OrbitApp
    {
        if ($app->instances()->exists()) {
            throw new ResourceOperationException(
                errorCode: 'app.has_instances',
                message: "App [{$app->slug}] still has instances.",
                status: 409,
            );
        }

        $app->delete();

        return $app;
    }
}
