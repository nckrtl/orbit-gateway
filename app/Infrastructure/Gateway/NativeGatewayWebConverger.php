<?php

declare(strict_types=1);

namespace App\Infrastructure\Gateway;

use App\Domain\Certificates\GatewayCertificateIssuer;
use App\Domain\Gateway\GatewayWebConverger;
use App\Infrastructure\Files\ProtectedFileWriter;

/** @mago-expect lint:excessive-parameter-list Gateway web convergence composes four explicit host service boundaries. */
final readonly class NativeGatewayWebConverger implements GatewayWebConverger
{
    public function __construct(
        private GatewayCertificateIssuer $certificates,
        private GatewayCaddyConfigRenderer $caddyRenderer,
        private GatewayFpmConfigRenderer $fpmRenderer,
        private ProtectedFileWriter $files,
        private GatewayCheckoutAccessConverger $checkout,
        private NativeGatewayCertificatePublisher $certificatePublisher,
        private NativeGatewayFpmConverger $fpm,
        private NativeGatewayCaddyConverger $caddy,
        private string $orbitHome,
        private string $checkoutPath,
    ) {}

    public function converge(string $hostname, string $wireguardAddress): void
    {
        $this->checkout->converge();
        $certificate = $this->certificates->issue($hostname, $wireguardAddress);
        $generatedDirectory = rtrim(string: $this->orbitHome, characters: '/').'/generated/gateway';
        $generatedFpmPool = $generatedDirectory.'/php-fpm-pool.conf';
        $generatedCaddy = $generatedDirectory.'/Caddyfile';
        $this->files->put(
            $generatedFpmPool,
            $this->fpmRenderer->renderPool($this->checkoutPath, $this->orbitHome),
            0o644,
        );
        $this->files->put(
            $generatedCaddy,
            $this->caddyRenderer->render($hostname, $wireguardAddress, $this->checkoutPath),
            0o644,
        );
        $this->certificatePublisher->publish($certificate);
        $this->fpm->converge($generatedFpmPool);
        $this->caddy->converge($generatedCaddy);
    }
}
