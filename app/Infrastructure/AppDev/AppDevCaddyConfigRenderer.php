<?php

declare(strict_types=1);

namespace App\Infrastructure\AppDev;

use Illuminate\Support\Collection;

final readonly class AppDevCaddyConfigRenderer
{
    /** @param Collection<int, AppDevSite> $sites */
    public function render(Collection $sites): string
    {
        if ($sites->isEmpty()) {
            return '# Orbit has no active app development sites.'.PHP_EOL;
        }

        return $sites
            ->sortBy('hostname')
            ->map(static fn (AppDevSite $site): string => <<<CADDY
                https://{$site->hostname} {
                    bind {$site->nodeAddress}
                    root * {$site->checkoutPath}/{$site->documentRoot}
                    tls {$site->certificateDirectory()}/cert.pem {$site->certificateDirectory()}/key.pem
                    encode zstd gzip
                    php_fastcgi unix/{$site->socketPath()}
                    file_server
                }
                CADDY)
            ->implode(PHP_EOL.PHP_EOL).PHP_EOL;
    }
}
