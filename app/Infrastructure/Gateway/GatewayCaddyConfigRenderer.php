<?php

declare(strict_types=1);

namespace App\Infrastructure\Gateway;

final readonly class GatewayCaddyConfigRenderer
{
    public function render(string $hostname, string $wireguardAddress, string $checkoutPath): string
    {
        return <<<CADDYFILE
            {$hostname}, {$wireguardAddress} {
                bind {$wireguardAddress}
                root * {$checkoutPath}/public
                tls /etc/caddy/orbit-cert-current/gateway.pem /etc/caddy/orbit-cert-current/gateway.key
                encode zstd gzip
                php_fastcgi unix//run/php/orbit-gateway.sock {
                    dial_timeout 10s
                    read_timeout 900s
                    write_timeout 900s
                }
                file_server
            }
            CADDYFILE.PHP_EOL;
    }
}
