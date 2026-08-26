<?php

declare(strict_types=1);

namespace App\Infrastructure\AppProd;

use Illuminate\Support\Collection;

final readonly class AppProdCaddyConfigRenderer
{
    /** @param Collection<int, AppProdSite> $sites */
    public function render(Collection $sites): string
    {
        if ($sites->isEmpty()) {
            return '# Orbit has no active app production sites.'.PHP_EOL;
        }

        return $sites
            ->sortBy('hostname')
            ->map(static fn (AppProdSite $site): string => <<<CADDY
                https://{$site->hostname} {
                    root * {$site->checkoutPath}/{$site->documentRoot}
                    encode zstd gzip
                    php_fastcgi unix/{$site->socketPath()}
                    file_server
                }
                CADDY)
            ->implode(PHP_EOL.PHP_EOL).PHP_EOL;
    }
}
