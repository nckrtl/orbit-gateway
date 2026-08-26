<?php

declare(strict_types=1);

namespace App\Infrastructure\MacOs;

use App\Domain\AppDev\RuntimeConvergenceException;
use App\Infrastructure\AppDev\AppDevSite;
use Illuminate\Support\Collection;

final readonly class MacOsAppDevCaddyConfigRenderer
{
    public function __construct(
        private MacOsFilesystemLayout $layout,
    ) {}

    /** @param Collection<int, AppDevSite> $sites */
    public function render(Collection $sites, ?string $nodeAddress = null): string
    {
        $address = $nodeAddress ?? $sites->first()?->nodeAddress;

        if (! is_string($address) || filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            throw new RuntimeConvergenceException(
                step: 'caddy-config',
                errorCode: 'app-dev.caddy_address_invalid',
                message: 'The macOS Caddy listener address is invalid.',
            );
        }

        $global = <<<CADDY
            {
                admin off
                http_port 8080
                https_port 8443
                default_bind {$address}
                servers {$address}:8443 {
                    protocols h1 h2
                }
            }
            CADDY;
        $renderedSites = $sites
            ->sortBy('hostname')
            ->map(function (AppDevSite $site) use ($address): string {
                $certificateDirectory = $this->layout->certificateCurrent($site->home, $site->scope);
                $socket = $this->layout->phpSocket($site->home, $site->scope);

                return <<<CADDY
                    http://{$site->hostname}:8080 {
                        bind {$address}
                        redir https://{host}{uri} permanent
                    }

                    https://{$site->hostname}:8443 {
                        bind {$address}
                        root * {$site->checkoutPath}/{$site->documentRoot}
                        tls {$certificateDirectory}/cert.pem {$certificateDirectory}/key.pem
                        encode zstd gzip
                        php_fastcgi unix/{$socket}
                        file_server
                    }
                    CADDY;
            })
            ->implode(PHP_EOL.PHP_EOL);

        return $renderedSites === ''
            ? $global.PHP_EOL
            : $global.PHP_EOL.PHP_EOL.$renderedSites.PHP_EOL;
    }
}
