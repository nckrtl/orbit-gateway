<?php

declare(strict_types=1);

namespace App\Infrastructure\Gateway;

final readonly class GatewayFpmConfigRenderer
{
    public function renderPool(string $checkoutPath, string $orbitHome): string
    {
        return <<<FPM
            [orbit-gateway]
            user = orbit
            group = orbit
            listen = /run/php/orbit-gateway.sock
            listen.owner = orbit
            listen.group = caddy
            listen.mode = 0660
            pm = ondemand
            pm.max_children = 10
            pm.process_idle_timeout = 10s
            pm.max_requests = 500
            request_terminate_timeout = 900s
            chdir = {$checkoutPath}
            catch_workers_output = yes
            clear_env = yes
            security.limit_extensions = .php
            env[HOME] = /home/orbit
            env[ORBIT_HOME] = {$orbitHome}
            env[PATH] = /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
            php_admin_value[opcache.validate_timestamps] = 1
            php_admin_value[opcache.revalidate_freq] = 0
            php_admin_value[max_execution_time] = 900
            FPM.PHP_EOL;
    }
}
