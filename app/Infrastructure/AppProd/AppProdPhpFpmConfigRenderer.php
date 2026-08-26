<?php

declare(strict_types=1);

namespace App\Infrastructure\AppProd;

use Illuminate\Support\Collection;

final readonly class AppProdPhpFpmConfigRenderer
{
    /** @param Collection<int, AppProdSite> $sites */
    public function render(Collection $sites): string
    {
        return $sites
            ->sortBy(static fn (AppProdSite $site): string => $site->scope())
            ->map(static fn (AppProdSite $site): string => <<<FPM
                [{$site->poolName()}]
                user = {$site->user()}
                group = {$site->user()}
                listen = {$site->socketPath()}
                listen.owner = {$site->user()}
                listen.group = caddy
                listen.mode = 0660
                pm = ondemand
                pm.max_children = 20
                pm.process_idle_timeout = 10s
                pm.max_requests = 500
                chdir = {$site->checkoutPath}
                catch_workers_output = yes
                access.log = /var/log/orbit/php-fpm/{$site->scope()}.access.log
                slowlog = /var/log/orbit/php-fpm/{$site->scope()}.slow.log
                request_slowlog_timeout = 10s
                clear_env = yes
                env[HOME] = {$site->appRoot()}
                env[USER] = {$site->user()}
                env[PATH] = /usr/local/bin:/usr/bin:/bin

                FPM)
            ->implode(PHP_EOL);
    }
}
