<?php

declare(strict_types=1);

namespace App\Infrastructure\MacOs;

use App\Infrastructure\AppDev\AppDevSite;
use Illuminate\Support\Collection;

final readonly class MacOsAppDevPhpFpmConfigRenderer
{
    public function __construct(
        private MacOsFilesystemLayout $layout,
    ) {}

    /** @param Collection<int, AppDevSite> $sites */
    public function render(
        string $version,
        Collection $sites,
        string $home,
        string $user,
        string $brewPrefix,
    ): string {
        $path = "{$brewPrefix}/bin:{$brewPrefix}/sbin:/usr/bin:/bin:/usr/sbin:/sbin";
        $healthSocket = $this->layout->phpHealthSocket($home, $version);
        $log = $this->layout->phpLog($home, $version);
        $global = <<<FPM
            [global]
            error_log = {$log}
            daemonize = no

            [orbit-health]
            listen = {$healthSocket}
            listen.mode = 0600
            pm = ondemand
            pm.max_children = 1
            pm.process_idle_timeout = 10s
            catch_workers_output = yes
            clear_env = no
            env[HOME] = {$home}
            env[USER] = {$user}
            env[PATH] = {$path}
            request_slowlog_timeout = 5s
            slowlog = {$log}.slow
            request_terminate_timeout = 120s
            FPM;
        $pools = $sites
            ->sortBy('scope')
            ->map(function (AppDevSite $site) use ($home, $user, $path, $log): string {
                $socket = $this->layout->phpSocket($home, $site->scope);

                return <<<FPM
                    [{$site->poolName()}]
                    listen = {$socket}
                    listen.mode = 0600
                    pm = ondemand
                    pm.max_children = 10
                    pm.process_idle_timeout = 10s
                    pm.max_requests = 500
                    chdir = {$site->checkoutPath}
                    catch_workers_output = yes
                    clear_env = no
                    env[HOME] = {$home}
                    env[USER] = {$user}
                    env[PATH] = {$path}
                    request_slowlog_timeout = 5s
                    slowlog = {$log}.slow
                    request_terminate_timeout = 120s
                    FPM;
            })
            ->implode(PHP_EOL.PHP_EOL);

        return $pools === ''
            ? $global.PHP_EOL
            : $global.PHP_EOL.PHP_EOL.$pools.PHP_EOL;
    }
}
