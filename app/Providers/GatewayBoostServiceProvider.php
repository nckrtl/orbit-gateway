<?php

declare(strict_types=1);

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Laravel\Boost\BoostServiceProvider;

final class GatewayBoostServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        if (! $this->app->runningInConsole()) {
            return;
        }

        if (! class_exists(BoostServiceProvider::class)) {
            return;
        }

        $this->app->register(new class($this->app) extends BoostServiceProvider {
            protected function registerRoutes(): void {}
        });
    }
}
